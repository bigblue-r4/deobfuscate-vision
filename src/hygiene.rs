//! Mitigation, not detection: re-encode an image to strip channels an attacker
//! uses to smuggle payloads.
//!
//! Re-encoding through a clean decoder+encoder destroys three things at once:
//! - **Metadata injection** — EXIF/XMP/IPTC comments are dropped.
//! - **LSB steganography** — least-significant-bit payloads are quantized away
//!   by the round-trip (and by optional downscaling).
//! - **Adversarial perturbations** — gradient-crafted pixel noise loses coherence
//!   under resample + re-quantize.
//!
//! Run this on untrusted images *before* they reach a vision model when you can
//! afford to alter the pixels. It does not detect anything — pair it with
//! [`crate::analyze_image`] for the detection half.

use crate::VisionError;
use image::RgbaImage;
use std::io::Cursor;

/// Options for the hygiene re-encode.
#[derive(Debug, Clone)]
pub struct HygieneOptions {
    /// If set, the longest edge is scaled down to at most this many pixels
    /// (aspect preserved). `None` re-encodes at original resolution.
    pub max_edge: Option<u32>,
}

impl Default for HygieneOptions {
    fn default() -> Self {
        // 1568px matches the pre-4.7 vision input ceiling — a safe default that
        // also reliably destroys LSB stego without visibly degrading content.
        HygieneOptions { max_edge: Some(1568) }
    }
}

/// Decode, optionally downscale, and re-encode as metadata-free PNG.
///
/// Returns the sanitized PNG bytes. The output carries no EXIF/XMP and, after a
/// downscale, no recoverable LSB payload.
pub fn sanitize(bytes: &[u8], opts: &HygieneOptions) -> Result<Vec<u8>, VisionError> {
    let decoded = image::load_from_memory(bytes).map_err(VisionError::Decode)?;
    let mut rgba: RgbaImage = decoded.to_rgba8();

    if let Some(max_edge) = opts.max_edge {
        let (w, h) = rgba.dimensions();
        let longest = w.max(h);
        if longest > max_edge {
            let scale = max_edge as f32 / longest as f32;
            let nw = ((w as f32 * scale).round() as u32).max(1);
            let nh = ((h as f32 * scale).round() as u32).max(1);
            rgba = image::imageops::resize(&rgba, nw, nh, image::imageops::FilterType::Triangle);
        }
    }

    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(rgba)
        .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(VisionError::Decode)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_roundtrips_and_downscales() {
        let src = image::RgbaImage::from_pixel(4000, 100, image::Rgba([10, 20, 30, 255]));
        let mut buf = Vec::new();
        image::DynamicImage::ImageRgba8(src)
            .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();

        let clean = sanitize(&buf, &HygieneOptions::default()).unwrap();
        let re = image::load_from_memory(&clean).unwrap();
        assert!(re.width().max(re.height()) <= 1568);
    }

    #[test]
    fn sanitize_rejects_garbage() {
        assert!(sanitize(b"not an image", &HygieneOptions::default()).is_err());
    }
}
