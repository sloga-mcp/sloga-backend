use std::io::Cursor;

use crate::utils::apply_icc_profile;
use image::{GenericImageView, ImageReader};
use revolt_database::Metadata;
use revolt_files::{image_size, is_animated, video_size};
use tempfile::NamedTempFile;

/// Intersection of what infer can detect and what image-rs supports
///
/// Note: imagesize crate also supports all of these, so we use that for quick size probing.
static SUPPORTED_IMAGE_MIME: [&str; 9] = [
    "image/avif",
    "image/bmp",
    "image/gif",
    "image/vnd.microsoft.icon",
    "image/jpeg",
    "image/jxl", // not supported by image-rs but we shim it
    "image/png",
    "image/tiff",
    "image/webp",
];

/// Generate metadata from file, using mime type as a hint
pub fn generate_metadata(f: &NamedTempFile, mime_type: &str) -> Metadata {
    if SUPPORTED_IMAGE_MIME.contains(&mime_type) {
        image_size(f)
            .map(|(width, height)| Metadata::Image {
                width: width as isize,
                height: height as isize,
                thumbhash: (|| {
                    // Pin the format from the mime rather than re-sniffing: image-rs
                    // only recognises an `avif` major brand, so an `avis`/`mif1` AVIF
                    // that infer and imagesize both accepted would silently yield no
                    // thumbhash here. See `reader_with_format` in revolt-files.
                    let mut reader = ImageReader::open(f).ok()?;
                    match image::ImageFormat::from_mime_type(mime_type) {
                        Some(format) => reader.set_format(format),
                        None => reader = reader.with_guessed_format().ok()?,
                    }
                    let mut decoder = reader.into_decoder().ok()?;
                    let icc_profile = image::ImageDecoder::icc_profile(&mut decoder)
                        .ok()
                        .flatten();
                    let mut img = image::DynamicImage::from_decoder(decoder).ok()?;

                    if let Some(icc) = icc_profile {
                        img = apply_icc_profile(img, &icc);
                    }

                    let img = img.thumbnail(100, 100);
                    let (width, height) = img.dimensions();
                    Some(thumbhash::rgba_to_thumb_hash(
                        width as usize,
                        height as usize,
                        &img.into_rgba8().into_raw(),
                    ))
                })(),
                animated: is_animated(f, mime_type).or(Some(false)),
            })
            .unwrap_or_default()
    } else if mime_type.starts_with("video/") {
        video_size(f)
            .map(|(width, height)| Metadata::Video {
                width: width as isize,
                height: height as isize,
            })
            .unwrap_or_default()
    } else if mime_type.starts_with("audio/") {
        Metadata::Audio
    } else if mime_type == "plain/text" {
        Metadata::Text
    } else {
        Metadata::File
    }
}

/// Subroutine to ensure data isn't corrupted
pub fn validate_from_metadata(
    reader: Cursor<Vec<u8>>,
    metadata: Metadata,
    mime_type: &str,
) -> Metadata {
    if let Metadata::Image { .. } = &metadata {
        if mime_type == "image/jxl" {
            // Check if we can read using jxl-oxide crate
            if jxl_oxide::JxlImage::builder()
                .read(reader)
                .inspect_err(|err| tracing::error!("Failed to read JXL! {err:?}"))
                .is_err()
            {
                return Metadata::File;
            }
        } else {
            // Pin the format from the mime for the same reason as `generate_metadata`
            // above: re-sniffing rejects an `avis`/`mif1` AVIF that infer already
            // accepted. NOTE: nothing calls this function today, so this arm is
            // untested -- it is pinned for consistency so the trap is not reintroduced
            // the day someone wires it up.
            let mut probe = image::ImageReader::new(reader);
            let probe = match image::ImageFormat::from_mime_type(mime_type) {
                Some(format) => {
                    probe.set_format(format);
                    Ok(probe)
                }
                None => probe
                    .with_guessed_format()
                    .inspect_err(|err| tracing::error!("Failed to read image! {err:?}")),
            };

            if matches!(probe.map(|f| f.decode()), Err(_) | Ok(Err(_))) {
                return Metadata::File;
            }
        }
    }

    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    /// The blur-up placeholder. Before AVIF decoding was enabled this silently came
    /// back `None` -- a soft failure that shows up as an image popping in without its
    /// blur, which is easy to miss. Assert it is actually produced.
    #[test]
    fn avif_metadata_includes_a_thumbhash() {
        let f = temp_file(include_bytes!(
            "../../../core/files/tests/assets/dice.avif"
        ));

        match generate_metadata(&f, "image/avif") {
            Metadata::Image {
                width,
                height,
                thumbhash,
                animated,
            } => {
                assert_eq!((width, height), (320, 240));
                assert!(thumbhash.is_some(), "AVIF should produce a thumbhash");
                assert_eq!(animated, Some(false));
            }
            other => panic!("expected Metadata::Image, got {other:?}"),
        }
    }

    /// The `avis`-major-brand file, through the real metadata path rather than the
    /// decoder directly: dimensions come from imagesize, the thumbhash from image-rs,
    /// and `animated` from the moov walk. All three have to agree.
    #[test]
    fn animated_avif_metadata_is_complete() {
        let f = temp_file(include_bytes!(
            "../../../core/files/tests/assets/anim-icos.avif"
        ));

        match generate_metadata(&f, "image/avif") {
            Metadata::Image {
                width,
                height,
                thumbhash,
                animated,
            } => {
                assert_eq!((width, height), (320, 240));
                assert!(
                    thumbhash.is_some(),
                    "an avis-major AVIF should still produce a thumbhash"
                );
                assert_eq!(animated, Some(true));
            }
            other => panic!("expected Metadata::Image, got {other:?}"),
        }
    }

    /// Control: a format that always worked, so a failure above is about AVIF rather
    /// than about `generate_metadata` being broken generally.
    #[test]
    fn png_metadata_includes_a_thumbhash() {
        let f = temp_file(include_bytes!(
            "../../../core/files/tests/assets/test.png"
        ));

        match generate_metadata(&f, "image/png") {
            Metadata::Image {
                width,
                height,
                thumbhash,
                ..
            } => {
                assert_eq!((width, height), (900, 900));
                assert!(thumbhash.is_some());
            }
            other => panic!("expected Metadata::Image, got {other:?}"),
        }
    }
}
