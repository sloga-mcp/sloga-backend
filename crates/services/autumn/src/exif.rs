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

                // Create a reader
                let mut cursor = Cursor::new(buf);

                // Decode the image
                let reader =
                    report_internal_error!(ImageReader::new(&mut cursor).with_guessed_format())?;
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
                        image::codecs::avif::AvifEncoder::new(&mut writer).write_image(
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
}
