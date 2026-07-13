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
                        animated: *animated,
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
