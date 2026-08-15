use anyhow::Result;
use image::{AnimationDecoder, DynamicImage, ImageBuffer, ImageReader};
use jxl_oxide::integration::JxlDecoder;
use revolt_config::report_internal_error;
use std::io::{BufRead, Read, Seek, SeekFrom};
use tempfile::NamedTempFile;
use tiny_skia::Pixmap;

use crate::{MediaError, MediaRepository};

/// Pin the decoder to the mime type we already determined, sniffing only when the
/// mime is one image-rs has no mapping for (e.g. our JXL shim).
///
/// Sniffing a second time is not merely redundant, it disagrees with the first pass.
/// `infer` picks the mime and accepts an AVIF whose ISOBMFF major brand is `avif` OR
/// `avis`; `imagesize` additionally accepts `mif1`/`miaf`. image-rs matches only a
/// literal `avif` at bytes 8..12, so anything else is reported as an unknown format
/// before the decoder is reached. ffmpeg writes `avis` for every multi-frame AVIF, so
/// without this the common case of an animated AVIF fails as "not an image" — which
/// surfaces to the user as a 500, not as a rejected upload.
fn reader_with_format<R: BufRead + Seek>(
    reader: ImageReader<R>,
    mime: &str,
) -> std::io::Result<ImageReader<R>> {
    let mut reader = reader;
    match image::ImageFormat::from_mime_type(mime) {
        Some(format) => {
            reader.set_format(format);
            Ok(reader)
        }
        None => reader.with_guessed_format(),
    }
}

/// Whether an ISOBMFF file (AVIF, HEIF) carries an image sequence rather than a single
/// still, detected by the presence of a top-level `moov` box.
///
/// This cannot be answered by decoding: image-rs implements `AnimationDecoder` for GIF,
/// WebP and APNG only, and its AVIF decoder reads just the primary item. An animated AVIF
/// carries BOTH — a still primary item in `meta`/`mdat` and the sequence in `moov` — so
/// decoding it succeeds and silently yields one frame. Walking the top-level boxes is the
/// only way to tell the two apart, and it is cheap: the header of each box gives its size,
/// so this seeks rather than reads.
fn isobmff_has_moov<R: Read + Seek>(reader: &mut R) -> bool {
    let Ok(total) = reader.seek(SeekFrom::End(0)) else {
        return false;
    };

    let mut pos: u64 = 0;
    while pos.saturating_add(8) <= total {
        if reader.seek(SeekFrom::Start(pos)).is_err() {
            return false;
        }

        let mut header = [0u8; 8];
        if reader.read_exact(&mut header).is_err() {
            return false;
        }

        let kind = &header[4..8];
        if kind == b"moov" {
            return true;
        }

        let mut size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let mut header_len: u64 = 8;
        if size == 1 {
            // 64-bit size follows the type
            let mut extended = [0u8; 8];
            if reader.read_exact(&mut extended).is_err() {
                return false;
            }
            size = u64::from_be_bytes(extended);
            header_len = 16;
        } else if size == 0 {
            // Runs to end of file, so there is nothing after it
            return false;
        }

        if size < header_len {
            return false;
        }
        match pos.checked_add(size) {
            Some(next) => pos = next,
            None => return false,
        }
    }

    false
}

pub struct MediaImpl {
    config: revolt_config::Files,
}

impl MediaImpl {
    pub async fn from_config() -> MediaImpl {
        MediaImpl {
            config: revolt_config::config().await.files,
        }
    }

    pub fn new(config: revolt_config::Files) -> MediaImpl {
        MediaImpl { config }
    }
}

impl MediaRepository for MediaImpl {
    fn image_size(&self, f: &NamedTempFile) -> Option<(usize, usize)> {
        if let Ok(size) = imagesize::size(f.path())
            .inspect_err(|err| tracing::error!("Failed to generate image size! {err:?}"))
        {
            Some((size.width, size.height))
        } else {
            None
        }
    }

    fn is_animated(&self, f: &NamedTempFile, mime: &str) -> Option<bool> {
        match mime {
            // Current behaviour is to assume GIFs are animated, this checks for at least 2 frames
            "image/gif" => {
                let file = std::fs::File::open(f.path()).ok()?;
                let reader = std::io::BufReader::new(file);
                let decoder = image::codecs::gif::GifDecoder::new(reader).ok()?;
                Some(decoder.into_frames().take(2).count() > 1)
            }
            "image/png" => {
                let file = std::fs::File::open(f.path()).ok()?;
                let reader = std::io::BufReader::new(file);
                let decoder = image::codecs::png::PngDecoder::new(reader).ok()?;
                decoder.is_apng().ok()
            }
            "image/webp" => {
                let file = std::fs::File::open(f.path()).ok()?;
                let reader = std::io::BufReader::new(file);
                let decoder = image::codecs::webp::WebPDecoder::new(reader).ok()?;
                Some(decoder.has_animation())
            }
            "image/avif" => {
                let file = std::fs::File::open(f.path()).ok()?;
                let mut reader = std::io::BufReader::new(file);
                Some(isobmff_has_moov(&mut reader))
            }
            _ => Some(false),
        }
    }

    fn image_size_vec(&self, v: &[u8], mime: &str) -> Option<(usize, usize)> {
        match mime {
            "image/svg+xml" => {
                let tree =
                    report_internal_error!(usvg::Tree::from_data(v, &Default::default())).ok()?;

                let size = tree.size();
                Some((size.width() as usize, size.height() as usize))
            }
            _ => {
                if let Ok(size) = imagesize::blob_size(v)
                    .inspect_err(|err| tracing::error!("Failed to generate image size! {err:?}"))
                {
                    Some((size.width, size.height))
                } else {
                    None
                }
            }
        }
    }

    fn decode_image<R: Read + BufRead + Seek>(
        &self,
        reader: &mut R,
        mime: &str,
    ) -> Result<DynamicImage, MediaError> {
        match mime {
            "image/jxl" => {
                let decoder =
                    JxlDecoder::new(reader).map_err(|e| MediaError::from(anyhow::anyhow!(e)))?;

                DynamicImage::from_decoder(decoder)
                    .map_err(|e| MediaError::from(anyhow::anyhow!(e)))
            }
            "image/svg+xml" => {
                let mut buf = Vec::new();
                reader
                    .read_to_end(&mut buf)
                    .map_err(|e| MediaError::from(anyhow::anyhow!(e)))?;

                let tree: usvg::Tree = usvg::Tree::from_data(&buf, &Default::default())
                    .map_err(|e| MediaError::from(anyhow::anyhow!(e)))?;

                let size = tree.size();
                let mut pixmap = Pixmap::new(size.width() as u32, size.height() as u32)
                    .ok_or_else(|| MediaError::ImageProcessingFailed {
                        cause: "failed to create Pixmap, likely zero sized".to_string(),
                    })?;

                let mut pixmap_mut = pixmap.as_mut();
                resvg::render(&tree, Default::default(), &mut pixmap_mut);

                Ok(DynamicImage::ImageRgba8(
                    ImageBuffer::from_vec(
                        size.width() as u32,
                        size.height() as u32,
                        pixmap.data().to_vec(),
                    )
                    .ok_or_else(|| MediaError::ImageProcessingFailed {
                        cause: "buffer is not big enough".to_string(),
                    })?,
                ))
            }
            _ => {
                let image: ImageReader<&mut R> =
                    reader_with_format(image::ImageReader::new(reader), mime)
                        .map_err(|e| MediaError::from(anyhow::anyhow!(e)))?;

                let image: Result<DynamicImage, MediaError> = image
                    .decode()
                    .map_err(|e| MediaError::from(anyhow::anyhow!(e)));

                image
            }
        }
    }

    fn is_valid_image<R: Read + BufRead + Seek>(&self, reader: &mut R, mime: &str) -> bool {
        match mime {
            "image/jxl" => jxl_oxide::JxlImage::builder()
                .read(reader)
                .inspect_err(|err| tracing::error!("Failed to read JXL! {err:?}"))
                .is_ok(),
            _ => !matches!(
                reader_with_format(image::ImageReader::new(reader), mime)
                    .inspect_err(|err| tracing::error!("Failed to read image! {err:?}"))
                    .map(|f| f.decode()),
                Err(_) | Ok(Err(_))
            ),
        }
    }

    fn create_thumbnail(&self, image: DynamicImage, tag: &str) -> Vec<u8> {
        let [w, h] = self.config.preview.get(tag).unwrap();

        let image = image.thumbnail(image.width().min(*w as u32), image.height().min(*h as u32));
        let image = match image {
            DynamicImage::ImageRgb8(_) => image,
            DynamicImage::ImageRgba8(_) => image,
            _ => {
                if image.has_alpha() {
                    image.to_rgba8().into()
                } else {
                    image.to_rgb8().into()
                }
            }
        };

        let encoder = webp::Encoder::from_image(&image).expect("Could not create encoder.");
        if self.config.webp_quality != 100.0 {
            encoder.encode(self.config.webp_quality).to_vec()
        } else {
            encoder.encode_lossless().to_vec()
        }
    }

    fn video_size(&self, f: &NamedTempFile) -> Option<(i64, i64)> {
        if let Ok(data) = ffprobe::ffprobe(f.path())
            .inspect_err(|err| tracing::error!("Failed to ffprobe file! {err:?}"))
        {
            for stream in data.streams {
                if let (Some(w), Some(h)) = (stream.width, stream.height) {
                    return Some((w, h));
                }
            }

            None
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{MediaImpl, MediaRepository};
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn asset_test_jpeg() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/test.jpeg");
        assert_eq!(media.image_size_vec(buf, "image/jpeg"), Some((655, 582)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/jpeg").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    #[tokio::test]
    async fn asset_test_jpeg_is_not_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/test.jpeg"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/jpeg"), Some(false));
    }

    #[tokio::test]
    async fn asset_test_jpeg_extra_bytes() {
        let media = MediaImpl::from_config().await;
        let buf = [
            &include_bytes!("../../tests/assets/test.jpeg")[..],
            &[0u8; 16],
        ]
        .concat();
        assert_eq!(media.image_size_vec(&buf, "image/jpeg"), Some((655, 582)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/jpeg").unwrap();
        media.create_thumbnail(image, "emojis");
    }

    #[tokio::test]
    async fn asset_test_png() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/test.png");
        assert_eq!(media.image_size_vec(buf, "image/png"), Some((900, 900)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/png").unwrap();
        media.create_thumbnail(image, "emojis");
    }

    #[tokio::test]
    async fn asset_test_png_is_not_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/test.png"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/png"), Some(false));
    }

    #[tokio::test]
    async fn asset_test_png_extra_bytes() {
        let media = MediaImpl::from_config().await;
        let buf = [
            &include_bytes!("../../tests/assets/test.png")[..],
            &[0u8; 16],
        ]
        .concat();
        assert_eq!(media.image_size_vec(&buf, "image/png"), Some((900, 900)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/png").unwrap();
        media.create_thumbnail(image, "emojis");
    }

    #[tokio::test]
    async fn asset_test_floating_point_png() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/test-float.png");
        assert_eq!(media.image_size_vec(buf, "image/png"), Some((300, 300)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/png").unwrap();
        media.create_thumbnail(image, "avatars");
    }

    #[tokio::test]
    async fn asset_test_corrupted_png() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/corrupted.png");
        assert_eq!(media.image_size_vec(buf, "image/png"), Some((900, 900)));

        let mut reader = Cursor::new(buf);
        media.decode_image(&mut reader, "image/png").unwrap_err();
    }

    #[tokio::test]
    async fn asset_test_animated_png() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/anim-icos.apng");
        assert_eq!(media.image_size_vec(buf, "image/png"), Some((128, 128)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/png").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    #[tokio::test]
    async fn asset_test_animated_png_is_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/anim-icos.apng"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/png"), Some(true));
    }

    #[tokio::test]
    async fn asset_test_jxl() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/dice.jxl");
        assert_eq!(media.image_size_vec(buf, "image/jxl"), Some((800, 600)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/jxl").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    #[tokio::test]
    async fn asset_test_animated_jxl() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/anim-icos.jxl");
        assert_eq!(media.image_size_vec(buf, "image/jxl"), Some((128, 128)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/jxl").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    #[tokio::test]
    async fn asset_test_webp() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/dice.webp");
        assert_eq!(media.image_size_vec(buf, "image/webp"), Some((800, 600)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/webp").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    #[tokio::test]
    async fn asset_test_webp_is_not_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/dice.webp"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/webp"), Some(false));
    }

    #[tokio::test]
    async fn asset_test_animated_webp() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/anim-icos.webp");
        assert_eq!(media.image_size_vec(buf, "image/webp"), Some((128, 128)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/webp").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    #[tokio::test]
    async fn asset_test_animated_webp_is_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/anim-icos.webp"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/webp"), Some(true));
    }

    #[tokio::test]
    async fn asset_test_animated_gif() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/anim-icos.gif");
        assert_eq!(media.image_size_vec(buf, "image/gif"), Some((128, 128)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/gif").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    #[tokio::test]
    async fn asset_test_animated_gif_is_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/anim-icos.gif"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/gif"), Some(true));
    }

    #[tokio::test]
    async fn asset_test_avif() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/dice.avif");
        assert_eq!(media.image_size_vec(buf, "image/avif"), Some((320, 240)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/avif").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    /// An AVIF whose ISOBMFF major brand is `avis` rather than `avif` — which is what
    /// ffmpeg writes for anything multi-frame.
    ///
    /// This is the regression test for the sniffer mismatch: `infer` picks `image/avif`
    /// for this file and `imagesize` reads its dimensions, but image-rs' own sniffer
    /// matches only a literal `avif` major brand. Before `reader_with_format` pinned the
    /// format, `decode_image` reported it as an unknown format and the upload 500'd.
    #[tokio::test]
    async fn asset_test_avif_avis_major_brand_still_decodes() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/anim-icos.avif");
        assert_eq!(&buf[8..12], b"avis", "fixture should have an avis major brand");
        assert_eq!(media.image_size_vec(buf, "image/avif"), Some((320, 240)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/avif").unwrap();
        media.create_thumbnail(image, "attachments");
    }

    /// Detected from the `moov` box, not by decoding — decoding an animated AVIF reads
    /// only its still primary item and succeeds with a single frame, so it cannot tell
    /// the two apart. Getting this right is what makes the serve path redirect to the
    /// original so the sequence actually plays, instead of thumbnailing one frame.
    #[tokio::test]
    async fn asset_test_animated_avif_is_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/anim-icos.avif"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/avif"), Some(true));
    }

    #[tokio::test]
    async fn asset_test_avif_is_not_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/dice.avif"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/avif"), Some(false));
    }

    /// An animated AVIF that also carries an Exif item: the extra item must not confuse
    /// the box walk, since `meta` grows and `mdat` moves.
    #[tokio::test]
    async fn asset_test_animated_avif_with_exif_is_animated() {
        let media = MediaImpl::from_config().await;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(include_bytes!("../../tests/assets/anim-exif-gps.avif"))
            .unwrap();
        assert_eq!(media.is_animated(&f, "image/avif"), Some(true));
    }

    #[tokio::test]
    async fn asset_test_avif_with_exif_decodes() {
        let media = MediaImpl::from_config().await;
        let buf = include_bytes!("../../tests/assets/exif-gps.avif");
        assert_eq!(media.image_size_vec(buf, "image/avif"), Some((320, 240)));

        let mut reader = Cursor::new(buf);
        let image = media.decode_image(&mut reader, "image/avif").unwrap();
        media.create_thumbnail(image, "attachments");
    }
}
