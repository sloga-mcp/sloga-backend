use std::io::Read;
use std::time::Duration;

use revolt_database::Metadata;
use revolt_result::{create_error, Result};
use tempfile::NamedTempFile;
use tokio::process::Command;

/// Audio codecs playable inside an MP4 container in Chromium
static MP4_SAFE_AUDIO: [&str; 3] = ["aac", "mp3", "opus"];

/// Audio codecs allowed inside a WebM container
static WEBM_SAFE_AUDIO: [&str; 2] = ["opus", "vorbis"];

/// Mime types that were already remuxed-with-metadata-strip before web transcoding
/// existed; failures for these must keep failing the upload so the metadata-stripping
/// guarantee is preserved. All other video mimes used to pass through untouched, so
/// a processing failure falls back to storing the original bytes.
static STRICT_MIME: [&str; 3] = ["video/mp4", "video/webm", "video/quicktime"];

/// Videos longer than this are never re-encoded (remux/copy still applies)
const MAX_TRANSCODE_SECS: f64 = 3600.0;

/// Generous ceilings; typical files finish in a fraction of these
const REMUX_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSCODE_TIMEOUT: Duration = Duration::from_secs(600);

enum StreamAction {
    Copy,
    Transcode,
}

struct Plan {
    /// "mp4" or "webm"
    container: &'static str,
    mime: &'static str,
    video: StreamAction,
    audio: StreamAction,
}

/// Ensure a video attachment is stored in a format the `<video>` element can play:
/// lossless remux when the codecs are already web-safe, re-encode to H.264/AAC
/// otherwise. Always strips container metadata. Returns the (possibly new) file
/// contents, probed metadata and mime type.
pub async fn process_video(
    file: &NamedTempFile,
    buf: Vec<u8>,
    metadata: Metadata,
    mime: &str,
) -> Result<(Vec<u8>, Metadata, String)> {
    let strict = STRICT_MIME.contains(&mime);

    let probe = match ffprobe::ffprobe(file.path()) {
        Ok(probe) => probe,
        Err(err) => {
            tracing::error!("Failed to ffprobe video! {err:?}");
            return if strict {
                Err(create_error!(InternalError))
            } else {
                Ok((buf, metadata, mime.to_owned()))
            };
        }
    };

    let video_codec = probe
        .streams
        .iter()
        .find(|s| s.codec_type.as_deref() == Some("video"))
        .and_then(|s| s.codec_name.as_deref())
        .unwrap_or_default()
        .to_owned();

    let audio_codecs: Vec<String> = probe
        .streams
        .iter()
        .filter(|s| s.codec_type.as_deref() == Some("audio"))
        .map(|s| s.codec_name.clone().unwrap_or_default())
        .collect();

    let duration: f64 = probe
        .format
        .duration
        .as_deref()
        .and_then(|d| d.parse().ok())
        .unwrap_or_default();

    let mut plan = if ["vp8", "vp9", "av1"].contains(&video_codec.as_str()) {
        Plan {
            container: "webm",
            mime: "video/webm",
            video: StreamAction::Copy,
            audio: if audio_codecs.iter().all(|c| WEBM_SAFE_AUDIO.contains(&c.as_str())) {
                StreamAction::Copy
            } else {
                StreamAction::Transcode
            },
        }
    } else if video_codec == "h264" {
        Plan {
            container: "mp4",
            mime: "video/mp4",
            video: StreamAction::Copy,
            audio: if audio_codecs.iter().all(|c| MP4_SAFE_AUDIO.contains(&c.as_str())) {
                StreamAction::Copy
            } else {
                StreamAction::Transcode
            },
        }
    } else {
        // HEVC, MPEG-4 ASP, WMV, MPEG-2, ProRes, MJPEG, ...
        Plan {
            container: "mp4",
            mime: "video/mp4",
            video: StreamAction::Transcode,
            audio: StreamAction::Transcode,
        }
    };

    // Refuse to spend CPU re-encoding very long videos; fall back to a plain
    // metadata-strip remux of the original container where we used to do one
    if matches!(plan.video, StreamAction::Transcode) && duration > MAX_TRANSCODE_SECS {
        if !strict {
            return Ok((buf, metadata, mime.to_owned()));
        }

        plan = Plan {
            container: match mime {
                "video/mp4" => "mp4",
                "video/webm" => "webm",
                "video/quicktime" => "mov",
                _ => unreachable!(),
            },
            mime: match mime {
                "video/mp4" => "video/mp4",
                "video/webm" => "video/webm",
                "video/quicktime" => "video/quicktime",
                _ => unreachable!(),
            },
            video: StreamAction::Copy,
            audio: StreamAction::Copy,
        };
    }

    match run_ffmpeg(file, &plan).await {
        Ok((out_file, out_buf)) => {
            // Probe the processed file again for its dimensions
            let new_metadata = crate::metadata::generate_metadata(&out_file, plan.mime);

            if matches!(new_metadata, Metadata::Video { .. }) || strict {
                Ok((out_buf, new_metadata, plan.mime.to_owned()))
            } else {
                tracing::warn!("Processed video failed re-probe, storing original ({mime})");
                Ok((buf, metadata, mime.to_owned()))
            }
        }
        Err(err) => {
            tracing::error!("Failed to process video ({mime}): {err}");
            if strict {
                Err(create_error!(InternalError))
            } else {
                Ok((buf, metadata, mime.to_owned()))
            }
        }
    }
}

/// Run ffmpeg according to the plan, returning the output file and its contents
async fn run_ffmpeg(
    file: &NamedTempFile,
    plan: &Plan,
) -> std::result::Result<(NamedTempFile, Vec<u8>), String> {
    let mut out_file = NamedTempFile::new().map_err(|e| e.to_string())?;

    let input = file
        .path()
        .to_str()
        .ok_or_else(|| "non-utf8 temp path".to_owned())?;
    let output = out_file
        .path()
        .to_str()
        .ok_or_else(|| "non-utf8 temp path".to_owned())?
        .to_owned();

    let mut args: Vec<String> = [
        // Overwrite the temporary file
        "-y",
        // Read original uploaded file
        "-i",
        input,
        // Strip any metadata and chapters
        "-map_metadata",
        "-1",
        "-map_chapters",
        "-1",
        // Keep the primary video stream and any audio; drop subtitles,
        // fonts and other data streams that break mp4/webm muxing
        "-map",
        "0:v:0",
        "-map",
        "0:a?",
        "-sn",
        "-dn",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    let transcoding = matches!(plan.video, StreamAction::Transcode)
        || matches!(plan.audio, StreamAction::Transcode);

    match plan.video {
        StreamAction::Copy => args.extend(["-c:v".into(), "copy".into()]),
        StreamAction::Transcode => args.extend(
            [
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-crf",
                "23",
                // 10-bit sources (HEVC) must come down to 8-bit for broad decode support
                "-pix_fmt",
                "yuv420p",
                // Cap width at 1080p-class, keep aspect ratio, force even dimensions
                "-vf",
                "scale='min(1920,iw)':-2",
            ]
            .into_iter()
            .map(String::from),
        ),
    }

    match plan.audio {
        StreamAction::Copy => args.extend(["-c:a".into(), "copy".into()]),
        StreamAction::Transcode => match plan.container {
            "webm" => args.extend(["-c:a".into(), "libopus".into(), "-b:a".into(), "128k".into()]),
            _ => args.extend(["-c:a".into(), "aac".into(), "-b:a".into(), "160k".into()]),
        },
    }

    // Front-load the moov atom so playback and seeking start immediately over HTTP
    if plan.container == "mp4" || plan.container == "mov" {
        args.extend(["-movflags".into(), "+faststart".into()]);
    }

    args.extend(["-f".into(), plan.container.to_owned(), output]);

    let timeout = if transcoding {
        TRANSCODE_TIMEOUT
    } else {
        REMUX_TIMEOUT
    };

    let result = tokio::time::timeout(
        timeout,
        Command::new("ffmpeg").args(&args).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "ffmpeg timed out".to_owned())?
    .map_err(|e| e.to_string())?;

    if !result.status.success() {
        return Err(format!(
            "ffmpeg exited with {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
                .lines()
                .last()
                .unwrap_or_default()
        ));
    }

    let mut buf = Vec::<u8>::new();
    out_file.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    if buf.is_empty() {
        return Err("ffmpeg produced an empty file".to_owned());
    }

    Ok((out_file, buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Command;

    /// Generate a 1 second test clip via ffmpeg, returning the temp file and its bytes
    fn generate_clip(vcodec: &str, acodec: &str, format: &str) -> (NamedTempFile, Vec<u8>) {
        let mut out = NamedTempFile::new().unwrap();
        let status = Command::new("ffmpeg")
            .args([
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=1:size=128x128:rate=10",
                "-f",
                "lavfi",
                "-i",
                "sine=duration=1",
                "-c:v",
                vcodec,
                "-c:a",
                acodec,
                "-shortest",
                "-f",
                format,
                out.path().to_str().unwrap(),
            ])
            .output()
            .expect("ffmpeg must be installed to run these tests")
            .status;
        assert!(status.success());

        let mut buf = Vec::new();
        out.read_to_end(&mut buf).unwrap();
        (out, buf)
    }

    /// Probe codec and container of raw video bytes
    fn probe(buf: &[u8]) -> (String, String) {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(buf).unwrap();
        f.flush().unwrap();

        let data = ffprobe::ffprobe(f.path()).unwrap();
        let codec = data
            .streams
            .iter()
            .find(|s| s.codec_type.as_deref() == Some("video"))
            .and_then(|s| s.codec_name.clone())
            .unwrap_or_default();
        (codec, data.format.format_name)
    }

    #[tokio::test]
    async fn mkv_with_web_safe_codecs_is_remuxed_to_mp4() {
        let (file, buf) = generate_clip("libx264", "aac", "matroska");
        let metadata = Metadata::Video {
            width: 128,
            height: 128,
        };

        let (out, metadata, mime) = process_video(&file, buf, metadata, "video/x-matroska")
            .await
            .unwrap();

        assert_eq!(mime, "video/mp4");
        assert!(matches!(metadata, Metadata::Video { .. }));
        let (codec, format) = probe(&out);
        assert_eq!(codec, "h264");
        assert!(format.contains("mp4"));
    }

    #[tokio::test]
    async fn avi_with_legacy_codec_is_transcoded_to_h264_mp4() {
        let (file, buf) = generate_clip("mpeg4", "mp3", "avi");
        let metadata = Metadata::Video {
            width: 128,
            height: 128,
        };

        let (out, metadata, mime) = process_video(&file, buf, metadata, "video/x-msvideo")
            .await
            .unwrap();

        assert_eq!(mime, "video/mp4");
        assert!(matches!(metadata, Metadata::Video { .. }));
        let (codec, format) = probe(&out);
        assert_eq!(codec, "h264");
        assert!(format.contains("mp4"));
    }

    /// Full upload-side chain: magic-byte sniff → metadata probe → web processing,
    /// exactly as `upload_file` drives it
    #[tokio::test]
    async fn upload_chain_classifies_and_converts_mkv() {
        let (mut file, buf) = generate_clip("libx264", "aac", "matroska");

        // infer cannot tell MKV from WebM (shared EBML magic), so MKVs arrive
        // as video/webm; the plan is chosen by actual codecs, not container
        let mime = crate::mime_type::determine_mime_type(&mut file, &buf, "clip.mkv");
        assert_eq!(mime, "video/webm");

        let metadata = crate::metadata::generate_metadata(&file, mime);
        assert!(matches!(metadata, Metadata::Video { .. }));

        let (_, metadata, mime) = process_video(&file, buf, metadata, mime).await.unwrap();
        assert_eq!(mime, "video/mp4");
        assert!(matches!(metadata, Metadata::Video { .. }));
    }

    #[tokio::test]
    async fn unreadable_lenient_video_falls_back_to_original() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not a video").unwrap();
        file.flush().unwrap();

        let metadata = Metadata::Video {
            width: 1,
            height: 1,
        };

        let (out, _, mime) = process_video(
            &file,
            b"not a video".to_vec(),
            metadata,
            "video/x-matroska",
        )
        .await
        .unwrap();

        assert_eq!(mime, "video/x-matroska");
        assert_eq!(out, b"not a video");
    }
}
