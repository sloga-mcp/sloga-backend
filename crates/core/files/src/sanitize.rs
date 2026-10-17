//! Clean an image the server fetched on a user's behalf before it is stored
//!
//! Imported server icons, banners, emoji and stickers come from a third party, so they
//! are treated as hostile: the format is pinned by magic bytes, the header dimensions
//! are checked before anything is decoded, the first frame must decode under explicit
//! limits, and metadata (EXIF and the GPS tags in it, XMP, comments, text chunks) is
//! removed. Animated images keep every frame: GIF, WebP and APNG are cleaned by walking
//! their structure and copying the image data through, never by re-encoding.

use std::fmt;
use std::io::Cursor;

use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::metadata::Orientation;
use image::{DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, ImageReader, Limits};

/// Bounds applied to an image before and while it is decoded
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageLimits {
    /// Largest accepted width or height, in pixels
    pub max_side: u32,
    /// Largest accepted width x height
    pub max_pixels: u64,
    /// Most memory the first-frame decode may allocate, in bytes
    pub max_alloc: u64,
}

/// An image with its metadata removed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedImage {
    /// The cleaned file
    pub bytes: Vec<u8>,
    /// `image/png` (also for APNG), `image/gif`, `image/jpeg` or `image/webp`
    pub mime: &'static str,
    /// Width after any EXIF orientation was applied
    pub width: u32,
    /// Height after any EXIF orientation was applied
    pub height: u32,
    /// Whether the file has more than one frame (read from its structure)
    pub animated: bool,
}

/// Why an image was refused
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeError {
    /// Not a PNG, APNG, GIF, JPEG or WebP
    NotAnImage,
    /// Over the configured dimensions, pixel count or allocation budget
    TooLarge,
    /// Malformed, truncated, or could not be decoded or re-encoded
    Decode,
}

impl fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SanitizeError::NotAnImage => "not a supported image",
            SanitizeError::TooLarge => "image is too large",
            SanitizeError::Decode => "image could not be decoded",
        })
    }
}

impl std::error::Error for SanitizeError {}

/// Formats accepted, by magic bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Png,
    Gif,
    Jpeg,
    WebP,
}

/// Every PNG begins with these eight bytes
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// Quality used when a JPEG has to be re-encoded to drop its metadata
///
/// Higher than the encoder's default of 75: these are icons and emoji that get shown
/// small and are re-encoded exactly once, so the extra bytes buy visibly fewer artifacts.
const JPEG_QUALITY: u8 = 90;

/// Validate an image, strip its metadata and report what it is
///
/// Fails closed: anything that does not parse as one of the accepted formats, or whose
/// structure is malformed anywhere a walk reaches, is refused rather than passed through.
pub fn sanitize_image(buf: Vec<u8>, limits: ImageLimits) -> Result<SanitizedImage, SanitizeError> {
    let kind = sniff(&buf).ok_or(SanitizeError::NotAnImage)?;

    // Dimensions from the header alone, so an image claiming to be enormous is refused
    // before a decoder ever sees it
    let size = imagesize::blob_size(&buf).map_err(|_| SanitizeError::Decode)?;
    let width = u32::try_from(size.width).map_err(|_| SanitizeError::TooLarge)?;
    let height = u32::try_from(size.height).map_err(|_| SanitizeError::TooLarge)?;
    check_dimensions(width, height, &limits)?;
    if width == 0 || height == 0 {
        return Err(SanitizeError::Decode);
    }

    match kind {
        Kind::Jpeg => reencode(&buf, ImageFormat::Jpeg, &limits, "image/jpeg"),
        Kind::Png => {
            let walked = walk_png(&buf, width, height)?;
            if !walked.animated {
                // A still PNG is re-encoded, which also applies any eXIf orientation
                // and drops everything after IEND (CVE-2023-21036)
                return reencode(&buf, ImageFormat::Png, &limits, "image/png");
            }

            // Re-encoding through image-rs would flatten an APNG to one frame, so its
            // metadata chunks are dropped in place instead. An eXIf orientation goes
            // with them unapplied; frames cannot be rotated without re-encoding them.
            validate_first_frame(&walked.bytes, ImageFormat::Png, &limits)?;
            Ok(SanitizedImage {
                bytes: walked.bytes,
                mime: "image/png",
                width,
                height,
                animated: true,
            })
        }
        Kind::Gif => {
            let (bytes, frames) = walk_gif(&buf, &limits)?;
            validate_first_frame(&bytes, ImageFormat::Gif, &limits)?;
            Ok(SanitizedImage {
                bytes,
                mime: "image/gif",
                width,
                height,
                animated: frames > 1,
            })
        }
        Kind::WebP => {
            // An EXIF orientation in a WebP is dropped unapplied, as for APNG: the
            // frames are copied through, not decoded and rotated
            let (bytes, animated) = walk_webp(&buf, width, height)?;
            validate_first_frame(&bytes, ImageFormat::WebP, &limits)?;
            Ok(SanitizedImage {
                bytes,
                mime: "image/webp",
                width,
                height,
                animated,
            })
        }
    }
}

/// Identify the format from its magic bytes
fn sniff(buf: &[u8]) -> Option<Kind> {
    if buf.starts_with(&PNG_SIGNATURE) {
        Some(Kind::Png)
    } else if buf.starts_with(b"GIF87a") || buf.starts_with(b"GIF89a") {
        Some(Kind::Gif)
    } else if buf.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(Kind::Jpeg)
    } else if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"WEBP" {
        Some(Kind::WebP)
    } else {
        None
    }
}

/// Refuse dimensions over either side limit or the pixel budget
fn check_dimensions(width: u32, height: u32, limits: &ImageLimits) -> Result<(), SanitizeError> {
    if width > limits.max_side
        || height > limits.max_side
        || u64::from(width) * u64::from(height) > limits.max_pixels
    {
        return Err(SanitizeError::TooLarge);
    }
    Ok(())
}

/// Open a decoder pinned to `format` with the decode limits applied
fn open_decoder<'a>(
    buf: &'a [u8],
    format: ImageFormat,
    limits: &ImageLimits,
) -> Result<impl ImageDecoder + 'a, SanitizeError> {
    // `Limits` is non-exhaustive, so it cannot be built as a literal
    let mut decode_limits = Limits::default();
    decode_limits.max_image_width = Some(limits.max_side);
    decode_limits.max_image_height = Some(limits.max_side);
    decode_limits.max_alloc = Some(limits.max_alloc);

    let mut reader = ImageReader::with_format(Cursor::new(buf), format);
    reader.limits(decode_limits);
    let decoder = reader.into_decoder().map_err(|_| SanitizeError::Decode)?;

    // The decoder's own view of the size is checked as well: it is what will actually
    // be allocated, whatever the header parser made of the file
    let (width, height) = decoder.dimensions();
    check_dimensions(width, height, limits)?;
    if decoder.total_bytes() > limits.max_alloc {
        return Err(SanitizeError::TooLarge);
    }

    Ok(decoder)
}

/// Decode the first frame and throw it away, proving the file is an image
fn validate_first_frame(
    buf: &[u8],
    format: ImageFormat,
    limits: &ImageLimits,
) -> Result<(), SanitizeError> {
    let decoder = open_decoder(buf, format, limits)?;
    DynamicImage::from_decoder(decoder).map_err(|_| SanitizeError::Decode)?;
    Ok(())
}

/// Decode a still image, apply its EXIF orientation and encode it again in the same
/// format, which leaves every metadata segment behind
///
/// The ICC profile is carried over: both the JPEG and the PNG encoder accept one, and
/// dropping it would visibly shift the colors of anything not authored in sRGB. Other
/// PNG color chunks (`gAMA`, `cHRM`, `sRGB`) are not carried over; image-rs does not
/// expose them to the encoder.
fn reencode(
    buf: &[u8],
    format: ImageFormat,
    limits: &ImageLimits,
    mime: &'static str,
) -> Result<SanitizedImage, SanitizeError> {
    let mut decoder = open_decoder(buf, format, limits)?;

    // Both of these read the metadata about to be thrown away. If either is unreadable
    // the image is kept un-rotated / un-profiled; nothing of the metadata survives.
    let icc_profile = decoder.icc_profile().ok().flatten();
    let orientation = decoder
        .orientation()
        .unwrap_or(Orientation::NoTransforms);

    let mut image = DynamicImage::from_decoder(decoder).map_err(|_| SanitizeError::Decode)?;
    image.apply_orientation(orientation);
    let icc_profile = icc_profile.filter(|icc| icc_matches(icc, image.color()));

    let mut bytes = Vec::new();
    let written = match format {
        ImageFormat::Jpeg => {
            let mut encoder = JpegEncoder::new_with_quality(&mut bytes, JPEG_QUALITY);
            if let Some(icc) = icc_profile {
                let _ = encoder.set_icc_profile(icc);
            }
            image.write_with_encoder(encoder)
        }
        ImageFormat::Png => {
            let mut encoder = PngEncoder::new(&mut bytes);
            if let Some(icc) = icc_profile {
                let _ = encoder.set_icc_profile(icc);
            }
            image.write_with_encoder(encoder)
        }
        _ => return Err(SanitizeError::Decode),
    };
    // An image we decoded but cannot write back out is refused, not stored unclean
    written.map_err(|_| SanitizeError::Decode)?;

    Ok(SanitizedImage {
        bytes,
        mime,
        width: image.width(),
        height: image.height(),
        animated: false,
    })
}

/// Whether an ICC profile describes the color space the pixels are written in
///
/// A CMYK JPEG decodes to RGB, so its CMYK profile no longer describes the pixels and
/// would tell a viewer to misread every one of them; such a profile is dropped.
fn icc_matches(icc: &[u8], color: image::ColorType) -> bool {
    // The data color space signature sits at bytes 16..20 of the profile header
    match icc.get(16..20) {
        Some(b"RGB ") => color.has_color(),
        Some(b"GRAY") => !color.has_color(),
        _ => false,
    }
}

/// PNG chunks copied through when an animated PNG is cleaned
///
/// Structural chunks, the animation (`acTL`/`fcTL`/`fdAT`) and the chunks that say how
/// to display the pixels. Everything else is dropped: `eXIf`, `tEXt`, `zTXt`, `iTXt` and
/// `tIME`, which autumn also strips, and any other ancillary chunk, since editors write
/// private chunks (`caNv`, `prVW`, `mkBF`, ...) that can carry arbitrary data.
const PNG_KEPT_CHUNKS: [&[u8]; 18] = [
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB",
    b"cICP", b"mDCv", b"cLLi", b"bKGD", b"pHYs", b"acTL", b"fcTL", b"fdAT",
];

/// A PNG with its metadata chunks removed
struct PngWalk {
    bytes: Vec<u8>,
    /// `acTL` before the first `IDAT` declares more than one frame
    animated: bool,
}

/// Walk a PNG's chunks, dropping metadata and reading whether it is animated
///
/// Ported from autumn's `strip_png_metadata_chunks` (crates/services/autumn/src/exif.rs),
/// with an allowlist in place of its denylist. A PNG is a sequence of length-prefixed
/// chunks, so metadata is removed by copying every other chunk through verbatim, which
/// keeps an animated PNG's frames byte for byte.
fn walk_png(buf: &[u8], width: u32, height: u32) -> Result<PngWalk, SanitizeError> {
    if buf.len() < PNG_SIGNATURE.len() || buf[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
        return Err(SanitizeError::Decode);
    }

    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(&PNG_SIGNATURE);

    let mut seen_idat = false;
    let mut frames: Option<u32> = None;

    let mut pos = PNG_SIGNATURE.len();
    loop {
        // Each chunk is a four byte big-endian length, a four byte type, that many
        // bytes of data, then a four byte CRC covering the type and the data.
        let data_start = pos.checked_add(8).ok_or(SanitizeError::Decode)?;
        if data_start > buf.len() {
            return Err(SanitizeError::Decode);
        }

        let length = be_u32(&buf[pos..pos + 4]) as usize;
        let kind = &buf[pos + 4..data_start];
        let data_end = data_start
            .checked_add(length)
            .ok_or(SanitizeError::Decode)?;
        let chunk_end = data_end.checked_add(4).ok_or(SanitizeError::Decode)?;
        if chunk_end > buf.len() {
            return Err(SanitizeError::Decode);
        }
        let data = &buf[data_start..data_end];

        match kind {
            // An `acTL` after the image data is ignored by decoders, so it is not
            // what makes the file animated
            b"acTL" if !seen_idat => {
                if data.len() != 8 {
                    return Err(SanitizeError::Decode);
                }
                frames = Some(be_u32(&data[0..4]));
            }
            b"IDAT" => seen_idat = true,
            b"fcTL" => {
                // Every frame must sit inside the canvas the header (and so the size
                // check) described
                if data.len() != 26 {
                    return Err(SanitizeError::Decode);
                }
                let frame_width = u64::from(be_u32(&data[4..8]));
                let frame_height = u64::from(be_u32(&data[8..12]));
                let x = u64::from(be_u32(&data[12..16]));
                let y = u64::from(be_u32(&data[16..20]));
                if x + frame_width > u64::from(width) || y + frame_height > u64::from(height) {
                    return Err(SanitizeError::Decode);
                }
            }
            _ => {}
        }

        if PNG_KEPT_CHUNKS.contains(&kind) {
            // Copied whole, so the CRC already in the file stays valid
            out.extend_from_slice(&buf[pos..chunk_end]);
        }

        pos = chunk_end;

        // Nothing past IEND is part of the image. Dropping it keeps the mitigation
        // for CVE-2023-21036: a short image written over a longer file leaves the
        // tail of the original readable beyond the end marker.
        if kind == b"IEND".as_slice() {
            return Ok(PngWalk {
                bytes: out,
                animated: frames.is_some_and(|frames| frames > 1),
            });
        }
    }
}

/// GIF application extensions that hold the loop count, and are kept
const GIF_LOOP_EXTENSIONS: [&[u8; 11]; 2] = [b"NETSCAPE2.0", b"ANIMEXTS1.0"];

/// Walk a GIF's blocks, dropping everything that is not image data, returning the
/// cleaned file and how many frames it has
///
/// Kept: the header, logical screen descriptor and global color table; every image
/// (descriptor, local color table and LZW data, verbatim); graphic control extensions
/// (frame delay, disposal, transparency); and the loop count. The last two are rebuilt
/// from their fixed fields rather than copied, so no trailing sub-blocks ride along.
/// Dropped: comment extensions (0xFE), every other application extension (XMP, ICC,
/// vendor data), plain text extensions (0x01, not rendered by browsers) and unknown
/// labels. A GIF that ends before its trailer is refused.
fn walk_gif(buf: &[u8], limits: &ImageLimits) -> Result<(Vec<u8>, usize), SanitizeError> {
    // Header (6) + logical screen descriptor (7)
    if buf.len() < 13 {
        return Err(SanitizeError::Decode);
    }
    let mut pos = 13 + color_table_len(buf[10]);
    if pos > buf.len() {
        return Err(SanitizeError::Decode);
    }

    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(&buf[..pos]);
    let mut frames = 0usize;

    loop {
        match buf.get(pos) {
            // Trailer: anything after it is not part of the image and is dropped
            Some(0x3b) => {
                out.push(0x3b);
                return Ok((out, frames));
            }
            // Image descriptor: separator, left, top, width, height, packed fields
            Some(0x2c) => {
                let descriptor = buf.get(pos..pos + 10).ok_or(SanitizeError::Decode)?;
                let frame_width = u16::from_le_bytes([descriptor[5], descriptor[6]]);
                let frame_height = u16::from_le_bytes([descriptor[7], descriptor[8]]);
                check_dimensions(frame_width.into(), frame_height.into(), limits)?;

                // Local color table, then the LZW minimum code size, then the data
                let data_start = pos + 10 + color_table_len(descriptor[9]) + 1;
                let end = skip_sub_blocks(buf, data_start)?;
                out.extend_from_slice(&buf[pos..end]);
                frames += 1;
                pos = end;
            }
            Some(0x21) => {
                let label = *buf.get(pos + 1).ok_or(SanitizeError::Decode)?;
                let body = pos + 2;
                // Validates every sub-block in the extension, so the fixed fields
                // read below are known to be in bounds
                let end = skip_sub_blocks(buf, body)?;

                match label {
                    // Graphic control: one four byte sub-block
                    0xf9 => {
                        if buf[body] != 4 {
                            return Err(SanitizeError::Decode);
                        }
                        out.extend_from_slice(&[0x21, 0xf9, 4]);
                        out.extend_from_slice(&buf[body + 1..body + 5]);
                        out.push(0);
                    }
                    // Application: an eleven byte identifier sub-block, then data
                    0xff if buf[body] == 11 => {
                        let identifier = &buf[body + 1..body + 12];
                        let data = body + 12;
                        // The loop sub-block is three bytes: id 1, then the count
                        if GIF_LOOP_EXTENSIONS.iter().any(|known| known[..] == *identifier)
                            && buf[data] == 3
                            && buf[data + 1] == 1
                        {
                            out.extend_from_slice(&[0x21, 0xff, 11]);
                            out.extend_from_slice(identifier);
                            out.extend_from_slice(&buf[data..data + 4]);
                            out.push(0);
                        }
                    }
                    // Comments, other application data, plain text and anything
                    // unrecognised
                    _ => {}
                }
                pos = end;
            }
            // Truncated, or a byte that starts no block
            _ => return Err(SanitizeError::Decode),
        }
    }
}

/// Size of the color table that a GIF packed-fields byte announces
fn color_table_len(packed: u8) -> usize {
    if packed & 0x80 != 0 {
        3 << ((packed & 0x07) + 1)
    } else {
        0
    }
}

/// Step over a run of GIF data sub-blocks, returning the offset after the terminator
fn skip_sub_blocks(buf: &[u8], mut pos: usize) -> Result<usize, SanitizeError> {
    loop {
        let size = *buf.get(pos).ok_or(SanitizeError::Decode)? as usize;
        pos += 1;
        if size == 0 {
            return Ok(pos);
        }
        pos = pos.checked_add(size).ok_or(SanitizeError::Decode)?;
        if pos > buf.len() {
            return Err(SanitizeError::Decode);
        }
    }
}

/// VP8X flag: the file is animated
const VP8X_ANIMATION: u8 = 0x02;
/// VP8X flag: an `XMP ` chunk is present
const VP8X_XMP: u8 = 0x04;
/// VP8X flag: an `EXIF` chunk is present
const VP8X_EXIF: u8 = 0x08;

/// Top-level WebP chunks copied through. Everything else, including `EXIF`, `XMP `
/// and unknown chunks (which readers are required to ignore), is dropped.
const WEBP_KEPT_CHUNKS: [&[u8]; 7] = [b"VP8X", b"VP8 ", b"VP8L", b"ALPH", b"ANIM", b"ANMF", b"ICCP"];

/// Chunks kept inside an `ANMF` frame: the frame's own alpha and bitstream. The format
/// allows unknown chunks here too, so they are dropped as at the top level.
const WEBP_FRAME_CHUNKS: [&[u8]; 3] = [b"ALPH", b"VP8 ", b"VP8L"];

/// Walk a WebP's RIFF chunks, dropping metadata, returning the cleaned file and whether
/// it is animated
///
/// The `EXIF` and `XMP ` flags in `VP8X` are cleared to match, every `ANMF` frame is
/// rebuilt with only its image chunks, and the RIFF size is rewritten for the new
/// length. Bytes past the RIFF size are dropped.
fn walk_webp(buf: &[u8], width: u32, height: u32) -> Result<(Vec<u8>, bool), SanitizeError> {
    if buf.len() < 12 {
        return Err(SanitizeError::Decode);
    }
    let riff_end = 8usize
        .checked_add(le_u32(&buf[4..8]) as usize)
        .ok_or(SanitizeError::Decode)?;
    if riff_end > buf.len() || riff_end < 12 {
        return Err(SanitizeError::Decode);
    }

    let mut out = Vec::with_capacity(riff_end);
    out.extend_from_slice(b"RIFF\0\0\0\0WEBP");
    let mut animated = false;

    for (fourcc, payload) in riff_chunks(buf, 12, riff_end)? {
        match fourcc {
            b"VP8X" => {
                if payload.len() < 10 {
                    return Err(SanitizeError::Decode);
                }
                animated |= payload[0] & VP8X_ANIMATION != 0;
                let mut vp8x = payload.to_vec();
                vp8x[0] &= !(VP8X_EXIF | VP8X_XMP);
                push_riff_chunk(&mut out, fourcc, &vp8x);
            }
            b"ANIM" => {
                animated = true;
                push_riff_chunk(&mut out, fourcc, payload);
            }
            b"ANMF" => {
                // Frame header: x/2, y/2, width-1, height-1, duration (24-bit each),
                // then one byte of flags
                if payload.len() < 16 {
                    return Err(SanitizeError::Decode);
                }
                let x = 2 * u64::from(le_u24(&payload[0..3]));
                let y = 2 * u64::from(le_u24(&payload[3..6]));
                let frame_width = u64::from(le_u24(&payload[6..9])) + 1;
                let frame_height = u64::from(le_u24(&payload[9..12])) + 1;
                if x + frame_width > u64::from(width) || y + frame_height > u64::from(height) {
                    return Err(SanitizeError::Decode);
                }

                let mut frame = payload[..16].to_vec();
                for (inner, data) in riff_chunks(payload, 16, payload.len())? {
                    if WEBP_FRAME_CHUNKS.contains(&inner) {
                        push_riff_chunk(&mut frame, inner, data);
                    }
                }
                push_riff_chunk(&mut out, fourcc, &frame);
            }
            _ if WEBP_KEPT_CHUNKS.contains(&fourcc) => push_riff_chunk(&mut out, fourcc, payload),
            _ => {}
        }
    }

    let riff_size = u32::try_from(out.len() - 8).map_err(|_| SanitizeError::Decode)?;
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());
    Ok((out, animated))
}

/// Split `buf[start..end]` into RIFF chunks: a fourcc, a little-endian size, the
/// payload, and a pad byte when the size is odd
fn riff_chunks(buf: &[u8], start: usize, end: usize) -> Result<Vec<(&[u8], &[u8])>, SanitizeError> {
    let mut chunks = Vec::new();
    let mut pos = start;
    while pos < end {
        let header_end = pos.checked_add(8).ok_or(SanitizeError::Decode)?;
        if header_end > end {
            return Err(SanitizeError::Decode);
        }
        let size = le_u32(&buf[pos + 4..header_end]) as usize;
        let payload_end = header_end
            .checked_add(size)
            .ok_or(SanitizeError::Decode)?;
        if payload_end > end {
            return Err(SanitizeError::Decode);
        }
        chunks.push((&buf[pos..pos + 4], &buf[header_end..payload_end]));
        // Some writers leave the pad byte off the last chunk; it carries nothing
        pos = (payload_end + (size & 1)).min(end);
    }
    Ok(chunks)
}

/// Append a RIFF chunk, padding it to an even length
fn push_riff_chunk(out: &mut Vec<u8>, fourcc: &[u8], payload: &[u8]) {
    out.extend_from_slice(fourcc);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        out.push(0);
    }
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn le_u24(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
    use image::codecs::jpeg::JpegDecoder;
    use image::codecs::png::PngDecoder;
    use image::codecs::webp::{WebPDecoder, WebPEncoder};
    use image::{AnimationDecoder, ExtendedColorType, Frame, RgbaImage};

    /// The limits the import pipeline uses for icons, banners, emoji and stickers
    const LIMITS: ImageLimits = ImageLimits {
        max_side: 4096,
        max_pixels: 16 * 1024 * 1024,
        max_alloc: 256 * 1024 * 1024,
    };

    /// A value no encoder would write by itself, so finding it means the GPS IFD survived
    const GPS_MARKER: &[u8] = b"GPS-SECRET-48.8584N-2.2945E";

    fn find(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    /// The assertion every metadata test leans on; see the control below
    fn assert_no_gps(bytes: &[u8]) {
        assert!(!find(bytes, b"Exif\0\0"), "GPS leak: an EXIF APP1 header survived");
        assert!(!find(bytes, GPS_MARKER), "GPS leak: the GPS IFD survived");
    }

    /// A little-endian TIFF block (an EXIF payload) holding an orientation and a GPS IFD
    fn exif_tiff(orientation: u16) -> Vec<u8> {
        let mut tiff = b"II\x2a\0".to_vec();
        tiff.extend_from_slice(&8u32.to_le_bytes());

        // IFD0 at 8: two entries, so the GPS IFD follows at 8 + 2 + 24 + 4 = 38
        tiff.extend_from_slice(&2u16.to_le_bytes());
        // Orientation, SHORT x 1, value inline
        tiff.extend_from_slice(&0x0112u16.to_le_bytes());
        tiff.extend_from_slice(&3u16.to_le_bytes());
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&orientation.to_le_bytes());
        tiff.extend_from_slice(&[0, 0]);
        // GPSInfo pointer, LONG x 1
        tiff.extend_from_slice(&0x8825u16.to_le_bytes());
        tiff.extend_from_slice(&4u16.to_le_bytes());
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&38u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(tiff.len(), 38);

        // GPS IFD at 38: two entries, so out-of-line data follows at 38 + 2 + 24 + 4 = 68
        tiff.extend_from_slice(&2u16.to_le_bytes());
        // GPSLatitudeRef, ASCII x 2, inline "N\0"
        tiff.extend_from_slice(&0x0001u16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&2u32.to_le_bytes());
        tiff.extend_from_slice(b"N\0\0\0");
        // GPSMapDatum, ASCII, out of line
        tiff.extend_from_slice(&0x0012u16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&(GPS_MARKER.len() as u32 + 1).to_le_bytes());
        tiff.extend_from_slice(&68u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(tiff.len(), 68);

        tiff.extend_from_slice(GPS_MARKER);
        tiff.push(0);
        tiff
    }

    /// A solid-color RGBA image
    fn rgba(width: u32, height: u32, color: [u8; 4]) -> RgbaImage {
        RgbaImage::from_pixel(width, height, image::Rgba(color))
    }

    /// A JPEG carrying a GPS EXIF block and, optionally, an ICC profile
    fn jpeg_with_exif(width: u32, height: u32, orientation: u16, icc: Option<&[u8]>) -> Vec<u8> {
        let pixels = DynamicImage::ImageRgba8(rgba(width, height, [200, 30, 30, 255])).to_rgb8();
        let mut out = Vec::new();
        let mut encoder = JpegEncoder::new_with_quality(&mut out, 90);
        encoder.set_exif_metadata(exif_tiff(orientation)).unwrap();
        if let Some(icc) = icc {
            encoder.set_icc_profile(icc.to_vec()).unwrap();
        }
        encoder
            .write_image(pixels.as_raw(), width, height, ExtendedColorType::Rgb8)
            .unwrap();
        out
    }

    // ---- PNG helpers ----------------------------------------------------------------

    /// Bitwise CRC-32 (the PNG polynomial), enough to build test chunks
    fn crc32(parts: &[&[u8]]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for part in parts {
            for &byte in *part {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xedb8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
        }
        !crc
    }

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
        chunk
    }

    /// Every chunk in a PNG as (type, data), read by structure rather than by scanning
    /// bytes, which could match inside compressed data
    fn png_chunks(buf: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
        let mut chunks = Vec::new();
        let mut pos = PNG_SIGNATURE.len();
        while pos + 12 <= buf.len() {
            let length = be_u32(&buf[pos..pos + 4]) as usize;
            let kind: [u8; 4] = buf[pos + 4..pos + 8].try_into().unwrap();
            chunks.push((kind, buf[pos + 8..pos + 8 + length].to_vec()));
            pos += 12 + length;
        }
        chunks
    }

    fn encode_png(image: &RgbaImage) -> Vec<u8> {
        let mut out = Vec::new();
        PngEncoder::new(&mut out)
            .write_image(image.as_raw(), image.width(), image.height(), ExtendedColorType::Rgba8)
            .unwrap();
        out
    }

    /// A still PNG with `extra` chunks spliced in straight after IHDR
    fn png_with_chunks(image: &RgbaImage, extra: &[Vec<u8>]) -> Vec<u8> {
        let png = encode_png(image);
        let ihdr_end = PNG_SIGNATURE.len() + 12 + 13;
        let mut out = png[..ihdr_end].to_vec();
        for chunk in extra {
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&png[ihdr_end..]);
        out
    }

    fn fctl(sequence: u32, width: u32, height: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // x
        data.extend_from_slice(&0u32.to_be_bytes()); // y
        data.extend_from_slice(&1u16.to_be_bytes()); // delay numerator
        data.extend_from_slice(&10u16.to_be_bytes()); // delay denominator
        data.extend_from_slice(&[0, 0]); // dispose, blend
        png_chunk(b"fcTL", &data)
    }

    /// A two-frame APNG with a `tEXt` chunk between the frames
    fn apng_two_frames() -> Vec<u8> {
        let first = encode_png(&rgba(4, 3, [255, 0, 0, 255]));
        let second = encode_png(&rgba(4, 3, [0, 0, 255, 255]));
        let first_chunks = png_chunks(&first);
        let idat = |chunks: &[([u8; 4], Vec<u8>)]| -> Vec<u8> {
            chunks
                .iter()
                .filter(|(kind, _)| kind == b"IDAT")
                .flat_map(|(_, data)| data.clone())
                .collect()
        };

        let mut actl = 2u32.to_be_bytes().to_vec();
        actl.extend_from_slice(&0u32.to_be_bytes());
        let mut fdat = 2u32.to_be_bytes().to_vec();
        fdat.extend_from_slice(&idat(&png_chunks(&second)));

        let mut out = PNG_SIGNATURE.to_vec();
        out.extend(png_chunk(b"IHDR", &first_chunks[0].1));
        out.extend(png_chunk(b"acTL", &actl));
        out.extend(fctl(0, 4, 3));
        out.extend(png_chunk(b"IDAT", &idat(&first_chunks)));
        out.extend(png_chunk(b"tEXt", b"Comment\0PNG-TEXT-SECRET"));
        out.extend(fctl(1, 4, 3));
        out.extend(png_chunk(b"fdAT", &fdat));
        out.extend(png_chunk(b"IEND", &[]));
        out
    }

    fn apng_frame_count(buf: &[u8]) -> usize {
        let decoder = PngDecoder::new(Cursor::new(buf)).unwrap();
        assert!(decoder.is_apng().unwrap(), "should still be an APNG");
        decoder.apng().unwrap().into_frames().collect_frames().unwrap().len()
    }

    // ---- WebP helpers ---------------------------------------------------------------

    /// Every top-level chunk in a WebP as (fourcc, payload)
    fn webp_chunks(buf: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
        riff_chunks(buf, 12, buf.len())
            .unwrap()
            .into_iter()
            .map(|(fourcc, data)| (fourcc.try_into().unwrap(), data.to_vec()))
            .collect()
    }

    /// Append a chunk to a WebP, set `flag` in its VP8X and fix the RIFF size
    fn webp_append(mut buf: Vec<u8>, fourcc: &[u8; 4], data: &[u8], flag: u8) -> Vec<u8> {
        push_riff_chunk(&mut buf, fourcc, data);
        assert_eq!(&buf[12..16], b"VP8X", "fixture needs the extended format");
        buf[20] |= flag;
        let size = (buf.len() - 8) as u32;
        buf[4..8].copy_from_slice(&size.to_le_bytes());
        buf
    }

    /// A lossless still WebP, optionally carrying EXIF (which makes the encoder write VP8X)
    fn encode_webp(image: &RgbaImage, exif: Option<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut encoder = WebPEncoder::new_lossless(&mut out);
        if let Some(exif) = exif {
            encoder.set_exif_metadata(exif).unwrap();
        }
        encoder
            .write_image(image.as_raw(), image.width(), image.height(), ExtendedColorType::Rgba8)
            .unwrap();
        out
    }

    /// A two-frame animated WebP carrying an EXIF chunk
    fn animated_webp_with_exif() -> Vec<u8> {
        let frame_payload = |color| -> Vec<u8> {
            let still = encode_webp(&rgba(4, 4, color), None);
            let (fourcc, data) = webp_chunks(&still).remove(0);
            assert_eq!(&fourcc, b"VP8L");
            let mut frame = Vec::new();
            frame.extend_from_slice(&[0, 0, 0]); // x / 2
            frame.extend_from_slice(&[0, 0, 0]); // y / 2
            frame.extend_from_slice(&[3, 0, 0]); // width - 1
            frame.extend_from_slice(&[3, 0, 0]); // height - 1
            frame.extend_from_slice(&[100, 0, 0]); // duration
            frame.push(0); // flags
            push_riff_chunk(&mut frame, b"VP8L", &data);
            // An unknown chunk inside the frame, which the format tolerates
            push_riff_chunk(&mut frame, b"META", b"WEBP-FRAME-SECRET");
            frame
        };

        let mut out = b"RIFF\0\0\0\0WEBP".to_vec();
        let mut vp8x = vec![VP8X_ANIMATION | 0x10, 0, 0, 0];
        vp8x.extend_from_slice(&[3, 0, 0, 3, 0, 0]);
        push_riff_chunk(&mut out, b"VP8X", &vp8x);
        push_riff_chunk(&mut out, b"ANIM", &[0, 0, 0, 0, 0, 0]);
        push_riff_chunk(&mut out, b"ANMF", &frame_payload([255, 0, 0, 255]));
        push_riff_chunk(&mut out, b"ANMF", &frame_payload([0, 255, 0, 255]));
        let size = (out.len() - 8) as u32;
        out[4..8].copy_from_slice(&size.to_le_bytes());
        webp_append(out, b"EXIF", &exif_tiff(1), VP8X_EXIF)
    }

    // ---- GIF helpers ----------------------------------------------------------------

    /// A two-frame looping GIF with a comment and an XMP application extension spliced
    /// in after the screen descriptor
    fn animated_gif_with_comment() -> Vec<u8> {
        let mut gif = Vec::new();
        {
            let mut encoder = GifEncoder::new(&mut gif);
            encoder.set_repeat(Repeat::Infinite).unwrap();
            encoder
                .encode_frames(vec![
                    Frame::new(rgba(4, 3, [255, 0, 0, 255])),
                    Frame::new(rgba(4, 3, [0, 0, 255, 255])),
                ])
                .unwrap();
        }

        let screen_end = 13 + color_table_len(gif[10]);
        let mut out = gif[..screen_end].to_vec();
        out.extend_from_slice(&[0x21, 0xfe, 18]);
        out.extend_from_slice(b"GIF-COMMENT-SECRET");
        out.push(0);
        out.extend_from_slice(&[0x21, 0xff, 11]);
        out.extend_from_slice(b"XMP DataXMP");
        out.push(15);
        out.extend_from_slice(b"GIF-XMP-SECRET!");
        out.push(0);
        out.extend_from_slice(&gif[screen_end..]);
        out
    }

    fn gif_frame_count(buf: &[u8]) -> usize {
        GifDecoder::new(Cursor::new(buf))
            .unwrap()
            .into_frames()
            .collect_frames()
            .unwrap()
            .len()
    }

    // ---- JPEG -----------------------------------------------------------------------

    #[test]
    fn jpeg_gps_exif_is_removed_and_output_decodes() {
        let input = jpeg_with_exif(8, 6, 1, None);
        let clean = sanitize_image(input, LIMITS).unwrap();

        assert_no_gps(&clean.bytes);
        assert_eq!(clean.mime, "image/jpeg");
        assert!(!clean.animated);
        assert_eq!((clean.width, clean.height), (8, 6));

        let decoded = image::load_from_memory_with_format(&clean.bytes, ImageFormat::Jpeg).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (8, 6));
    }

    /// The control for `assert_no_gps`: the same assertion over the unmodified input must
    /// fail, or the test above would pass whatever the sanitiser did
    #[test]
    #[should_panic(expected = "GPS leak")]
    fn gps_assertion_fails_on_unstripped_input() {
        assert_no_gps(&jpeg_with_exif(8, 6, 1, None));
    }

    #[test]
    fn jpeg_orientation_is_applied() {
        // Orientation 6 = rotate 90 degrees clockwise to display, so 2x1 becomes 1x2
        let clean = sanitize_image(jpeg_with_exif(2, 1, 6, None), LIMITS).unwrap();
        assert_eq!((clean.width, clean.height), (1, 2));

        let decoded = image::load_from_memory_with_format(&clean.bytes, ImageFormat::Jpeg).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (1, 2));
        assert_no_gps(&clean.bytes);
    }

    /// Profile bytes with the given data color space signature in the header
    fn icc_profile(space: &[u8; 4]) -> Vec<u8> {
        let mut icc: Vec<u8> = (0..=255u8).cycle().take(600).collect();
        icc[16..20].copy_from_slice(space);
        icc
    }

    #[test]
    fn jpeg_icc_profile_is_kept() {
        let icc = icc_profile(b"RGB ");
        let clean = sanitize_image(jpeg_with_exif(8, 6, 1, Some(&icc)), LIMITS).unwrap();

        let mut decoder = JpegDecoder::new(Cursor::new(&clean.bytes)).unwrap();
        assert_eq!(decoder.icc_profile().unwrap(), Some(icc));
        assert_no_gps(&clean.bytes);
    }

    #[test]
    fn icc_profile_for_another_color_space_is_dropped() {
        // As a CMYK JPEG's profile would be once its pixels are decoded to RGB
        let icc = icc_profile(b"CMYK");
        let clean = sanitize_image(jpeg_with_exif(8, 6, 1, Some(&icc)), LIMITS).unwrap();

        let mut decoder = JpegDecoder::new(Cursor::new(&clean.bytes)).unwrap();
        assert_eq!(decoder.icc_profile().unwrap(), None);
    }

    // ---- PNG / APNG -----------------------------------------------------------------

    #[test]
    fn static_png_is_reencoded_without_metadata() {
        let input = png_with_chunks(
            &rgba(2, 1, [10, 20, 30, 255]),
            &[
                png_chunk(b"tEXt", b"Comment\0PNG-TEXT-SECRET"),
                png_chunk(b"eXIf", &exif_tiff(6)),
            ],
        );
        let clean = sanitize_image(input, LIMITS).unwrap();

        assert_eq!(clean.mime, "image/png");
        assert!(!clean.animated);
        // The eXIf orientation was applied before the chunk was dropped
        assert_eq!((clean.width, clean.height), (1, 2));
        let kinds: Vec<[u8; 4]> = png_chunks(&clean.bytes).into_iter().map(|(k, _)| k).collect();
        assert!(!kinds.contains(b"tEXt") && !kinds.contains(b"eXIf"), "{kinds:?}");
        assert!(!find(&clean.bytes, b"PNG-TEXT-SECRET"));
        assert_no_gps(&clean.bytes);
        image::load_from_memory_with_format(&clean.bytes, ImageFormat::Png).unwrap();
    }

    #[test]
    fn apng_keeps_frames_and_loses_text() {
        let input = apng_two_frames();
        assert_eq!(apng_frame_count(&input), 2, "fixture should have two frames");

        let clean = sanitize_image(input, LIMITS).unwrap();
        assert_eq!(clean.mime, "image/png");
        assert!(clean.animated);
        assert_eq!((clean.width, clean.height), (4, 3));
        assert_eq!(apng_frame_count(&clean.bytes), 2);

        let kinds: Vec<[u8; 4]> = png_chunks(&clean.bytes).into_iter().map(|(k, _)| k).collect();
        assert!(!kinds.contains(b"tEXt"), "{kinds:?}");
        assert!(!find(&clean.bytes, b"PNG-TEXT-SECRET"));
    }

    #[test]
    fn png_with_a_one_frame_actl_is_not_animated() {
        let mut actl = 1u32.to_be_bytes().to_vec();
        actl.extend_from_slice(&0u32.to_be_bytes());
        let input = png_with_chunks(&rgba(3, 3, [1, 2, 3, 255]), &[png_chunk(b"acTL", &actl)]);
        let clean = sanitize_image(input, LIMITS).unwrap();
        assert!(!clean.animated);
    }

    #[test]
    fn truncated_png_chunk_stream_is_refused() {
        let input = apng_two_frames();
        let cut = input[..input.len() - 20].to_vec();
        assert_eq!(sanitize_image(cut, LIMITS), Err(SanitizeError::Decode));
    }

    // ---- WebP -----------------------------------------------------------------------

    #[test]
    fn webp_exif_and_xmp_are_removed() {
        let input = encode_webp(&rgba(5, 3, [9, 9, 9, 255]), Some(exif_tiff(1)));
        let input = webp_append(input, b"XMP ", b"<x:xmpmeta>WEBP-XMP-SECRET</x:xmpmeta>", VP8X_XMP);
        let fourccs: Vec<[u8; 4]> = webp_chunks(&input).into_iter().map(|(k, _)| k).collect();
        assert!(fourccs.contains(b"EXIF") && fourccs.contains(b"XMP "), "{fourccs:?}");

        let clean = sanitize_image(input, LIMITS).unwrap();
        assert_eq!(clean.mime, "image/webp");
        assert!(!clean.animated);
        assert_eq!((clean.width, clean.height), (5, 3));

        let chunks = webp_chunks(&clean.bytes);
        let fourccs: Vec<[u8; 4]> = chunks.iter().map(|(k, _)| *k).collect();
        assert!(!fourccs.contains(b"EXIF") && !fourccs.contains(b"XMP "), "{fourccs:?}");
        let (_, vp8x) = chunks.iter().find(|(k, _)| k == b"VP8X").unwrap();
        assert_eq!(vp8x[0] & (VP8X_EXIF | VP8X_XMP), 0, "metadata flags cleared");
        assert_eq!(le_u32(&clean.bytes[4..8]) as usize, clean.bytes.len() - 8);
        assert!(!find(&clean.bytes, b"WEBP-XMP-SECRET"));
        assert_no_gps(&clean.bytes);

        let decoded = image::load_from_memory_with_format(&clean.bytes, ImageFormat::WebP).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (5, 3));
    }

    #[test]
    fn animated_webp_keeps_frames() {
        let input = animated_webp_with_exif();
        let clean = sanitize_image(input, LIMITS).unwrap();

        assert!(clean.animated);
        assert_eq!((clean.width, clean.height), (4, 4));
        assert_no_gps(&clean.bytes);
        assert!(!find(&clean.bytes, b"WEBP-FRAME-SECRET"));
        assert_eq!(le_u32(&clean.bytes[4..8]) as usize, clean.bytes.len() - 8);

        let frames = webp_chunks(&clean.bytes)
            .into_iter()
            .filter(|(k, _)| k == b"ANMF")
            .count();
        assert_eq!(frames, 2);

        let decoder = WebPDecoder::new(Cursor::new(&clean.bytes)).unwrap();
        assert!(decoder.has_animation());
        assert_eq!(decoder.into_frames().collect_frames().unwrap().len(), 2);
    }

    // ---- GIF ------------------------------------------------------------------------

    #[test]
    fn animated_gif_keeps_frames_and_loses_comments() {
        let input = animated_gif_with_comment();
        assert!(find(&input, b"GIF-COMMENT-SECRET") && find(&input, b"GIF-XMP-SECRET"));
        assert_eq!(gif_frame_count(&input), 2, "fixture should have two frames");

        let clean = sanitize_image(input, LIMITS).unwrap();
        assert_eq!(clean.mime, "image/gif");
        assert!(clean.animated);
        assert_eq!((clean.width, clean.height), (4, 3));
        assert!(!find(&clean.bytes, b"GIF-COMMENT-SECRET"));
        assert!(!find(&clean.bytes, b"XMP DataXMP"));
        assert!(!find(&clean.bytes, b"GIF-XMP-SECRET"));
        // The infinite loop survives
        assert!(find(&clean.bytes, b"NETSCAPE2.0\x03\x01\x00\x00\x00"));
        assert_eq!(gif_frame_count(&clean.bytes), 2);
    }

    #[test]
    fn single_frame_gif_is_not_animated() {
        let mut gif = Vec::new();
        {
            let mut encoder = GifEncoder::new(&mut gif);
            encoder
                .encode_frame(Frame::new(rgba(3, 2, [0, 255, 0, 255])))
                .unwrap();
        }
        let clean = sanitize_image(gif, LIMITS).unwrap();
        assert!(!clean.animated);
        assert_eq!((clean.width, clean.height), (3, 2));
    }

    #[test]
    fn truncated_gif_is_refused() {
        let input = animated_gif_with_comment();
        // Inside the second frame's data: the trailer and part of the image are gone
        let cut = input[..input.len() - 6].to_vec();
        assert_eq!(sanitize_image(cut, LIMITS), Err(SanitizeError::Decode));

        // Header and screen descriptor only
        let header = input[..13].to_vec();
        assert_eq!(sanitize_image(header, LIMITS), Err(SanitizeError::Decode));
    }

    // ---- Limits and rejection -------------------------------------------------------

    #[test]
    fn oversized_header_is_refused_before_decoding() {
        // An IHDR claiming 30000x30000 and no image data at all: a decode would fail
        // with `Decode`, so `TooLarge` shows the header check ran first
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&30000u32.to_be_bytes());
        ihdr.extend_from_slice(&30000u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend(png_chunk(b"IHDR", &ihdr));
        assert_eq!(sanitize_image(png, LIMITS), Err(SanitizeError::TooLarge));

        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&30000u16.to_le_bytes());
        gif.extend_from_slice(&30000u16.to_le_bytes());
        gif.extend_from_slice(&[0, 0, 0]);
        assert_eq!(sanitize_image(gif, LIMITS), Err(SanitizeError::TooLarge));
    }

    #[test]
    fn pixel_budget_is_enforced_separately_from_side_length() {
        let limits = ImageLimits {
            max_side: 10_000,
            max_pixels: 100,
            max_alloc: LIMITS.max_alloc,
        };
        let png = encode_png(&rgba(20, 20, [0, 0, 0, 255]));
        assert_eq!(sanitize_image(png.clone(), limits), Err(SanitizeError::TooLarge));
        assert!(sanitize_image(png, LIMITS).is_ok());
    }

    #[test]
    fn garbage_is_not_an_image() {
        assert_eq!(
            sanitize_image(b"definitely not an image, just text".to_vec(), LIMITS),
            Err(SanitizeError::NotAnImage)
        );
        assert_eq!(sanitize_image(Vec::new(), LIMITS), Err(SanitizeError::NotAnImage));
        // A real format that is not on the list
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0; 64]);
        assert_eq!(sanitize_image(bmp, LIMITS), Err(SanitizeError::NotAnImage));
    }

    #[test]
    fn magic_bytes_with_a_broken_body_fail_to_decode() {
        let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0];
        jpeg.extend_from_slice(&[0x55; 40]);
        assert_eq!(sanitize_image(jpeg, LIMITS), Err(SanitizeError::Decode));
    }
}
