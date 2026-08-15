use std::io::Cursor;

use crate::utils::apply_icc_profile;
use exif::Reader;
use image::{ImageEncoder, ImageReader};
use revolt_config::report_internal_error;
use revolt_database::Metadata;
use revolt_result::Result;
use tempfile::NamedTempFile;

macro_rules! encode_with_icc {
    ($encoder:expr, $icc:expr, $image:expr, $width:expr, $height:expr, $color:expr) => {{
        let mut encoder = $encoder;
        if let Some(icc) = $icc {
            let _ = encoder.set_icc_profile(icc.clone());
        }
        encoder.write_image($image, $width, $height, $color)
    }};
}

/// Strip EXIF data from given file and produce new file, metadata and mime type
///
/// Videos are additionally remuxed or transcoded into a web-playable format,
/// which may change the mime type (see [`crate::video::process_video`]).
pub async fn strip_metadata(
    file: NamedTempFile,
    buf: Vec<u8>,
    metadata: Metadata,
    mime: &str,
) -> Result<(Vec<u8>, Metadata, String)> {
    match &metadata {
        Metadata::Image {
            width: _,
            height: _,
            thumbhash,
            animated,
        } => match mime {
            // // little_exif does not appear to parse JPEGs correctly? had 2/2 files fail
            // "image/jpeg" | "image/png" => {
            //     // use little_exif to strip metadata except for orientation and colour profile
            //     // PNGs must also be re-encoded to mitigate CVE-2023-21036
            //     let metadata = revolt_little_exif::metadata::Metadata::new_from_path_with_filetype(
            //         file.path(),
            //         match mime {
            //             "image/jpeg" => revolt_little_exif::filetype::FileExtension::JPEG,
            //             "image/png" => revolt_little_exif::filetype::FileExtension::PNG {
            //                 as_zTXt_chunk: true,
            //             },
            //             _ => unreachable!(),
            //         },
            //     )
            //     .unwrap();
            //     dbg!(metadata.data());
            //     todo!()
            // }
            // Apply orientation manually & strip all other EXIF data
            "image/jpeg" | "image/png" | "image/avif" | "image/tiff" => {
                // Animated PNGs must not go through the re-encode below: image-rs'
                // PngEncoder only ever writes a single still frame, so it silently
                // flattens the animation while `animated` still reports true. The
                // serve path then skips thumbnail generation *and* redirects to an
                // "original" that no longer moves. Drop the metadata chunks in place
                // instead, which keeps every frame byte for byte.
                if mime == "image/png" && matches!(animated, Some(true)) {
                    if let Some(stripped) = strip_png_metadata_chunks(&buf) {
                        return Ok((stripped, metadata.clone(), mime.to_owned()));
                    }

                    // Chunk stream did not parse, so fall through and re-encode:
                    // losing the animation is preferable to leaving EXIF (and the
                    // GPS tags in it) on a file we could not otherwise clean. The
                    // metadata below records that it is no longer animated.
                }

                // AVIF never goes through the re-encode below if it can be avoided.
                // rav1e costs ~40s of CPU for a 12MP image at the encoder's default
                // speed and ~15s at speed 8, all of it synchronous inside the upload
                // request — a handful of concurrent uploads would saturate the worker
                // pool, and there is no megapixel cap to bound it. Zeroing the metadata
                // items in place is effectively free, lossless for the pixels, and keeps
                // animated AVIF animated (image-rs decodes only the primary item, so the
                // re-encode would silently flatten it).
                if mime == "image/avif" {
                    if let Some(stripped) = strip_avif_metadata_items(&buf) {
                        return Ok((stripped, metadata.clone(), mime.to_owned()));
                    }

                    // Unparseable as AVIF: fall through and re-encode rather than store
                    // a file we could not clean. Slow, but this is the rare path.
                }

                // Create a reader
                let mut cursor = Cursor::new(buf);

                // Decode the image, pinning the format from the mime this arm already
                // matched on. Re-sniffing here disagrees with the mime `infer` chose:
                // image-rs accepts only an `avif` major brand, so an `avis` AVIF (what
                // ffmpeg writes for anything multi-frame) fails as an unknown format
                // and the upload 500s. See `reader_with_format` in revolt-files.
                let mut reader = ImageReader::new(&mut cursor);
                match image::ImageFormat::from_mime_type(mime) {
                    Some(format) => reader.set_format(format),
                    None => reader = report_internal_error!(reader.with_guessed_format())?,
                }
                let mut decoder = report_internal_error!(reader.into_decoder())?;
                let mut icc_profile =
                    report_internal_error!(image::ImageDecoder::icc_profile(&mut decoder))?;
                let mut image = report_internal_error!(image::DynamicImage::from_decoder(decoder))?;

                // Reset read position
                cursor.set_position(0);

                // Extract orientation data
                let exif_reader = Reader::new();
                let rotation = match exif_reader.read_from_container(&mut cursor) {
                    Ok(exif) => match exif.get_field(exif::Tag::Orientation, exif::In::PRIMARY) {
                        Some(orientation) => orientation.value.get_uint(0).unwrap_or_default(),
                        _ => 0,
                    },
                    _ => 0,
                };

                // Create a buffer to write to
                let mut bytes: Vec<u8> = Vec::new();
                let mut writer = Cursor::new(&mut bytes);

                // Apply the EXIF rotation
                // See https://jdhao.github.io/2019/07/31/image_rotation_exif_info/
                image = match &rotation {
                    2 => image.fliph(),
                    3 => image.rotate180(),
                    4 => image.rotate180().fliph(),
                    5 => image.rotate90().fliph(),
                    6 => image.rotate90(),
                    7 => image.rotate270().fliph(),
                    8 => image.rotate270(),
                    _ => image,
                };

                if let Some(icc) = &icc_profile {
                    image = apply_icc_profile(image, icc);
                    icc_profile = None;
                }

                let color_type = image.color();
                let width = image.width();
                let height = image.height();

                report_internal_error!(match mime {
                    "image/jpeg" => encode_with_icc!(
                        image::codecs::jpeg::JpegEncoder::new(&mut writer),
                        &icc_profile,
                        image.as_bytes(),
                        width,
                        height,
                        color_type.into()
                    ),
                    "image/png" => encode_with_icc!(
                        image::codecs::png::PngEncoder::new(&mut writer),
                        &icc_profile,
                        image.as_bytes(),
                        width,
                        height,
                        color_type.into()
                    ),
                    "image/avif" => {
                        // avif encoder doesn't implement set_icc_profile currently
                        //
                        // Speed 8 rather than `AvifEncoder::new`'s default of 4: this runs
                        // synchronously inside the upload request, and rav1e at speed 4 costs
                        // seconds of CPU for a phone-sized image. Quality stays at the
                        // default 80. Encoding is at least threaded — `ravif/threading` rides
                        // in on the `rayon` feature.
                        image::codecs::avif::AvifEncoder::new_with_speed_quality(&mut writer, 8, 80)
                            .write_image(
                                image.as_bytes(),
                                width,
                                height,
                                color_type.into(),
                            )
                    }
                    "image/tiff" => encode_with_icc!(
                        image::codecs::tiff::TiffEncoder::new(&mut writer),
                        &icc_profile,
                        image.as_bytes(),
                        width,
                        height,
                        color_type.into()
                    ),
                    _ => unreachable!(),
                })?;

                Ok((
                    bytes,
                    Metadata::Image {
                        width: width as isize,
                        height: height as isize,
                        thumbhash: thumbhash.clone(),
                        // Every encoder above writes exactly one frame, so whatever
                        // came in, what we just wrote out is static. Saying so keeps
                        // the serve path from skipping the thumbnail for a file that
                        // no longer has anything to animate.
                        animated: animated.map(|_| false),
                    },
                    mime.to_owned(),
                ))
            }
            // JXLs store EXIF data but we don't have the ability to write them
            "image/jxl" => Ok((buf, metadata, mime.to_owned())),
            // All other images that cannot store EXIF data
            _ => Ok((buf, metadata, mime.to_owned())),
        },
        // Remux or transcode into a web-playable format, stripping metadata in the process
        Metadata::Video { .. } => crate::video::process_video(&file, buf, metadata, mime).await,
        // all other file types don't store EXIF data
        _ => Ok((buf, metadata, mime.to_owned())),
    }
}

/// HEIF item types that carry metadata: `Exif` is EXIF (including GPS), `mime` is
/// normally XMP. Everything else in an AVIF's item list is image data or describes
/// how to display it.
const AVIF_METADATA_ITEM_TYPES: [&[u8]; 2] = [b"Exif", b"mime"];

/// Strip metadata from an AVIF without decoding it
///
/// Unlike PNG, an AVIF cannot be rebuilt by copying the parts we want through: item
/// payloads live in `mdat` and are addressed by ABSOLUTE file offsets recorded in
/// `iloc`, and for an animated file again in the `moov`'s `stco`. Removing bytes would
/// invalidate every one of those offsets, and a stale offset is a silent corruption —
/// the decoder reads the wrong bytes rather than failing.
///
/// So instead of removing the Exif item, overwrite its payload in place with zeros.
/// That is a SAME-LENGTH edit: every offset in both tables stays correct, no box size
/// changes, the image bitstream is untouched, and an animated AVIF keeps every frame.
/// The metadata bytes themselves are genuinely gone, which is what matters.
///
/// Returns `None` if this is not parseable as an AVIF; the caller is expected to fall
/// back to re-encoding rather than store the file unstripped.
fn strip_avif_metadata_items(buf: &[u8]) -> Option<Vec<u8>> {
    let meta = find_box(buf, 0, buf.len(), b"meta")?;
    // `meta` is a FullBox, so its children start after four bytes of version/flags
    let children = (meta.0 + 12, meta.1);

    let item_ids = avif_metadata_item_ids(buf, children)?;
    if item_ids.is_empty() {
        // Nothing to strip, but the file parsed: hand back an unchanged copy rather
        // than `None`, so the caller does not needlessly re-encode.
        return Some(buf.to_vec());
    }

    let mut out = buf.to_vec();
    for extent in avif_item_extents(buf, children)? {
        if !item_ids.contains(&extent.item_id) {
            continue;
        }
        // Construction methods 1 and 2 are `idat`- and item-relative rather than file
        // offsets. They are legal but absent from anything we have seen; refuse rather
        // than zero the wrong range.
        if extent.construction_method != 0 {
            return None;
        }
        let end = extent.offset.checked_add(extent.length)?;
        if end > out.len() {
            return None;
        }
        out[extent.offset..end].fill(0);
    }

    Some(out)
}

/// Find a direct child box of the given type, returning `(content_start, box_end)`
fn find_box(buf: &[u8], start: usize, end: usize, want: &[u8]) -> Option<(usize, usize)> {
    let mut pos = start;
    while pos + 8 <= end {
        let size = u32::from_be_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        let kind = &buf[pos + 4..pos + 8];
        let size = if size == 0 { end - pos } else { size };
        if size < 8 || pos.checked_add(size)? > end {
            return None;
        }
        if kind == want {
            return Some((pos, pos + size));
        }
        pos += size;
    }
    None
}

/// Walk `meta` -> `iinf` -> `infe` collecting the IDs of items that carry metadata
fn avif_metadata_item_ids(buf: &[u8], (start, end): (usize, usize)) -> Option<Vec<u16>> {
    let (iinf_start, iinf_end) = find_box(buf, start, end, b"iinf")?;
    let version = *buf.get(iinf_start + 8)?;
    // FullBox header, then a 2-byte (v0) or 4-byte entry_count before the infe children
    let mut pos = iinf_start + 12 + if version == 0 { 2 } else { 4 };

    let mut ids = Vec::new();
    while pos + 8 <= iinf_end {
        let size = u32::from_be_bytes(buf.get(pos..pos + 4)?.try_into().ok()?) as usize;
        if size < 8 || pos.checked_add(size)? > iinf_end {
            return None;
        }
        if &buf[pos + 4..pos + 8] == b"infe" {
            let infe_version = *buf.get(pos + 8)?;
            // Only v2/v3 carry an item_type, which is what we match on
            if infe_version >= 2 {
                let id_width = if infe_version == 3 { 4 } else { 2 };
                let mut q = pos + 12;
                let item_id = if id_width == 2 {
                    u16::from_be_bytes(buf.get(q..q + 2)?.try_into().ok()?)
                } else {
                    // A 32-bit item ID cannot be represented downstream; refuse rather
                    // than truncate it into the wrong item.
                    return None;
                };
                q += id_width + 2; // item_ID, then item_protection_index
                if AVIF_METADATA_ITEM_TYPES.contains(&buf.get(q..q + 4)?) {
                    ids.push(item_id);
                }
            }
        }
        pos += size;
    }
    Some(ids)
}

/// Where one item's bytes live, as recorded in `iloc`
struct AvifExtent {
    item_id: u16,
    /// Absolute offset into the file (when `construction_method` is 0)
    offset: usize,
    length: usize,
    construction_method: u8,
}

/// Parse `iloc` into the location of every item's payload
fn avif_item_extents(buf: &[u8], (start, end): (usize, usize)) -> Option<Vec<AvifExtent>> {
    let (iloc_start, _) = find_box(buf, start, end, b"iloc")?;
    let version = *buf.get(iloc_start + 8)?;
    let mut pos = iloc_start + 12;

    let sizes = *buf.get(pos)?;
    let (offset_size, length_size) = ((sizes >> 4) as usize, (sizes & 0xf) as usize);
    pos += 1;
    let base_offset_size = (*buf.get(pos)? >> 4) as usize;
    pos += 1;

    let item_count = u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?);
    pos += 2;

    let read = |pos: &mut usize, width: usize| -> Option<usize> {
        if width == 0 {
            return Some(0);
        }
        let mut value = 0usize;
        for byte in buf.get(*pos..*pos + width)? {
            value = value.checked_mul(256)?.checked_add(*byte as usize)?;
        }
        *pos += width;
        Some(value)
    };

    let mut out = Vec::new();
    for _ in 0..item_count {
        let item_id = u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?);
        pos += 2;
        let construction_method = if version >= 1 {
            let raw = read(&mut pos, 2)?;
            (raw & 0xf) as u8
        } else {
            0
        };
        pos += 2; // data_reference_index
        let base = read(&mut pos, base_offset_size)?;
        let extent_count = read(&mut pos, 2)?;
        for _ in 0..extent_count {
            let offset = read(&mut pos, offset_size)?;
            let length = read(&mut pos, length_size)?;
            out.push(AvifExtent {
                item_id,
                offset: base.checked_add(offset)?,
                length,
                construction_method,
            });
        }
    }
    Some(out)
}

/// Every PNG begins with these eight bytes
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// PNG chunks that can carry EXIF (including GPS), XMP, free-form text or a timestamp
///
/// Anything not listed here is either structural (`IHDR`, `IDAT`, `IEND`, and the
/// `acTL`/`fcTL`/`fdAT` chunks that make up the animation) or describes how to
/// display the pixels (`PLTE`, `tRNS`, `iCCP`, `gAMA`, `sRGB`, ...), so it is kept —
/// dropping the colour chunks would visibly change the image.
const PNG_METADATA_CHUNKS: [&[u8]; 5] = [b"eXIf", b"tEXt", b"zTXt", b"iTXt", b"tIME"];

/// Strip metadata from a PNG without touching its pixel data
///
/// A PNG is just a sequence of length-prefixed chunks, so metadata can be removed by
/// copying every other chunk through verbatim. This is what lets an animated PNG keep
/// its animation: re-encoding through image-rs would collapse it to a single frame.
///
/// Returns `None` if this is not a PNG or its chunk stream is malformed; the caller is
/// expected to fall back to re-encoding rather than store the file unstripped.
fn strip_png_metadata_chunks(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < PNG_SIGNATURE.len() || buf[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
        return None;
    }

    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(&PNG_SIGNATURE);

    let mut pos = PNG_SIGNATURE.len();
    loop {
        // Each chunk is a four byte big-endian length, a four byte type, that many
        // bytes of data, then a four byte CRC covering the type and the data.
        let data_start = pos.checked_add(8)?;
        if data_start > buf.len() {
            return None;
        }

        let length = u32::from_be_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        let kind = &buf[pos + 4..data_start];
        let chunk_end = data_start.checked_add(length)?.checked_add(4)?;
        if chunk_end > buf.len() {
            return None;
        }

        if !PNG_METADATA_CHUNKS.contains(&kind) {
            // Copied whole, so the CRC already in the file stays valid
            out.extend_from_slice(&buf[pos..chunk_end]);
        }

        pos = chunk_end;

        // Nothing past IEND is part of the image. Dropping it keeps the mitigation
        // for CVE-2023-21036 that the re-encode used to give us for free: a short
        // image written over a longer file leaves the tail of the original readable
        // beyond the end marker.
        if kind == b"IEND".as_slice() {
            return Some(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{codecs::png::PngDecoder, AnimationDecoder};
    use std::io::Write;

    const ANIMATED_PNG: &[u8] = include_bytes!("../../../core/files/tests/assets/anim-icos.apng");
    const STILL_PNG: &[u8] = include_bytes!("../../../core/files/tests/assets/test.png");

    /// Frames in the animated PNG fixture
    const ANIMATED_PNG_FRAMES: usize = 48;

    /// Decode a PNG and count its frames, asserting it is animated at all
    fn frame_count(buf: &[u8]) -> usize {
        let decoder = PngDecoder::new(Cursor::new(buf.to_vec())).expect("should decode as PNG");
        assert!(
            decoder.is_apng().unwrap(),
            "should still be an animated PNG"
        );
        decoder.apng().unwrap().into_frames().count()
    }

    /// Walk a PNG and collect its chunk types in order
    ///
    /// Scanning the raw bytes for a chunk name would also hit the same four bytes
    /// occurring by chance inside compressed image data, so read the structure.
    fn chunk_types(buf: &[u8]) -> Vec<String> {
        let mut types = Vec::new();
        let mut pos = PNG_SIGNATURE.len();

        while pos + 8 <= buf.len() {
            let length = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            types.push(String::from_utf8_lossy(&buf[pos + 4..pos + 8]).into_owned());
            pos += 12 + length;
        }

        types
    }

    /// Build a well-formed chunk: length, type, data, then the CRC over type and data
    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(kind);
        hasher.update(data);

        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
        chunk
    }

    /// Splice chunks in just after IHDR, where an encoder writing them would
    ///
    /// IHDR is always the first chunk and its data is always 13 bytes wide.
    fn insert_after_ihdr(buf: &[u8], chunks: &[Vec<u8>]) -> Vec<u8> {
        let ihdr_end = PNG_SIGNATURE.len() + 12 + 13;

        let mut out = buf[..ihdr_end].to_vec();
        for chunk in chunks {
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&buf[ihdr_end..]);
        out
    }

    /// An animated PNG carrying EXIF, as a camera or editor would produce
    fn animated_png_with_metadata() -> Vec<u8> {
        insert_after_ihdr(
            ANIMATED_PNG,
            &[
                // A minimal little-endian TIFF header with zero entries, which is
                // all the shape we need — nothing here parses it, it just has to
                // be recognisably an eXIf chunk.
                png_chunk(b"eXIf", b"II\x2a\x00\x08\x00\x00\x00\x00\x00"),
                png_chunk(b"tEXt", b"Comment\x00uploaded from somewhere"),
            ],
        )
    }

    fn image_metadata(width: isize, height: isize, animated: bool) -> Metadata {
        Metadata::Image {
            width,
            height,
            thumbhash: None,
            animated: Some(animated),
        }
    }

    fn temp_file(buf: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(buf).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn strips_metadata_chunks_but_keeps_every_frame() {
        let with_metadata = animated_png_with_metadata();

        // Negative control: the chunks we spliced in are well-formed enough that
        // the input really is a readable animated PNG carrying metadata before we
        // strip anything, so the assertions below cannot pass vacuously.
        assert_eq!(frame_count(&with_metadata), ANIMATED_PNG_FRAMES);
        let before = chunk_types(&with_metadata);
        assert!(before.contains(&"eXIf".to_owned()) && before.contains(&"tEXt".to_owned()));

        let stripped = strip_png_metadata_chunks(&with_metadata).expect("should parse");

        assert_eq!(frame_count(&stripped), ANIMATED_PNG_FRAMES);

        let after = chunk_types(&stripped);
        for kind in PNG_METADATA_CHUNKS {
            let kind = String::from_utf8_lossy(kind).into_owned();
            assert!(
                !after.contains(&kind),
                "{kind} chunk should have been removed"
            );
        }
        // The chunks that carry the animation have to survive
        assert!(after.contains(&"acTL".to_owned()));
        assert_eq!(
            after.iter().filter(|t| *t == "fcTL").count(),
            ANIMATED_PNG_FRAMES
        );

        // The fixture carries no metadata of its own, so stripping the version we
        // spliced into should land back on the original bytes exactly.
        assert_eq!(stripped, ANIMATED_PNG);
    }

    #[test]
    fn drops_anything_trailing_iend() {
        let mut padded = ANIMATED_PNG.to_vec();
        padded.extend_from_slice(b"recoverable tail of a longer image");

        let stripped = strip_png_metadata_chunks(&padded).expect("should parse");

        assert_eq!(stripped, ANIMATED_PNG);
    }

    #[test]
    fn rejects_input_it_cannot_walk() {
        // Not a PNG at all
        assert!(strip_png_metadata_chunks(STILL_PNG.get(1..).unwrap()).is_none());
        // Truncated part way through the chunk stream
        assert!(strip_png_metadata_chunks(&ANIMATED_PNG[..2048]).is_none());
        // Chunk claiming more data than the file holds
        let overrun = insert_after_ihdr(ANIMATED_PNG, &[b"\xff\xff\xff\xf0tEXtxx".to_vec()]);
        assert!(strip_png_metadata_chunks(&overrun).is_none());
    }

    #[tokio::test]
    async fn strip_metadata_keeps_animated_png_animated() {
        let buf = animated_png_with_metadata();
        let (out, metadata, mime) = strip_metadata(
            temp_file(&buf),
            buf.clone(),
            image_metadata(128, 128, true),
            "image/png",
        )
        .await
        .unwrap();

        assert_eq!(mime, "image/png");
        assert_eq!(frame_count(&out), ANIMATED_PNG_FRAMES);
        assert_eq!(metadata, image_metadata(128, 128, true));
    }

    #[tokio::test]
    async fn strip_metadata_still_re_encodes_a_static_png() {
        let (out, metadata, mime) = strip_metadata(
            temp_file(STILL_PNG),
            STILL_PNG.to_vec(),
            image_metadata(900, 900, false),
            "image/png",
        )
        .await
        .unwrap();

        assert_eq!(mime, "image/png");
        assert_ne!(out, STILL_PNG, "a static PNG should still be re-encoded");
        assert_eq!(metadata, image_metadata(900, 900, false));
    }

    /// An AVIF carrying a real Exif item (Make/Model plus a GPS IFD at 51°30'N 000°07'W).
    /// The re-encode rebuilds the file from decoded pixels, so the Exif item cannot
    /// survive — this asserts the GPS coordinates are actually gone from the bytes we
    /// store, which is the whole point of this code path.
    const EXIF_AVIF: &[u8] = include_bytes!("../../../core/files/tests/assets/exif-gps.avif");

    const ANIMATED_EXIF_AVIF: &[u8] =
        include_bytes!("../../../core/files/tests/assets/anim-exif-gps.avif");

    #[tokio::test]
    async fn strip_metadata_removes_exif_from_avif() {
        assert!(
            find_bytes(EXIF_AVIF, b"SlogaTestCam").is_some(),
            "fixture should carry Exif before stripping"
        );

        let (out, metadata, mime) = strip_metadata(
            temp_file(EXIF_AVIF),
            EXIF_AVIF.to_vec(),
            image_metadata(320, 240, false),
            "image/avif",
        )
        .await
        .unwrap();

        assert_eq!(mime, "image/avif");
        assert_eq!(metadata, image_metadata(320, 240, false));
        assert!(
            find_bytes(&out, b"SlogaTestCam").is_none(),
            "camera make should not survive the strip"
        );
        assert!(
            find_bytes(&out, b"AVIF-EXIF-FIXTURE").is_none(),
            "camera model should not survive the strip"
        );

        assert_in_place_metadata_only_edit(EXIF_AVIF, &out);
    }

    #[tokio::test]
    async fn strip_metadata_keeps_animated_avif_intact() {
        let (out, _, mime) = strip_metadata(
            temp_file(ANIMATED_EXIF_AVIF),
            ANIMATED_EXIF_AVIF.to_vec(),
            image_metadata(320, 240, true),
            "image/avif",
        )
        .await
        .unwrap();

        assert_eq!(mime, "image/avif");
        assert!(
            find_bytes(&out, b"SlogaTestCam").is_none(),
            "GPS-bearing Exif should not survive the strip"
        );

        // The sequence samples live in mdat and are addressed by offsets in both `iloc`
        // and the moov's `stco`. Proving the edit touched nothing but the Exif payload
        // is what proves every frame, and every offset, survived.
        assert_in_place_metadata_only_edit(ANIMATED_EXIF_AVIF, &out);
    }

    /// Assert the strip was a same-length, in-place edit that zeroed exactly one
    /// contiguous run — i.e. it rewrote metadata and nothing else. A re-encode would
    /// fail every one of these.
    fn assert_in_place_metadata_only_edit(before: &[u8], after: &[u8]) {
        assert_eq!(
            before.len(),
            after.len(),
            "strip must not change the file length, or every iloc/stco offset breaks"
        );

        let differing: Vec<usize> = (0..before.len())
            .filter(|&i| before[i] != after[i])
            .collect();
        assert!(!differing.is_empty(), "nothing was stripped");
        assert!(
            differing.iter().all(|&i| after[i] == 0),
            "changed bytes should have been zeroed"
        );

        // Not every byte in the stripped range necessarily *changes* — a TIFF is full of
        // zero bytes already (next-IFD offsets, the high bytes of small integers,
        // padding). So assert the span between the first and last change is entirely
        // zero in the output, rather than that every byte in it differs.
        let (first, last) = (differing[0], *differing.last().unwrap());
        assert!(
            after[first..=last].iter().all(|&b| b == 0),
            "the stripped range should be entirely zeroed, not edited piecemeal"
        );
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}
