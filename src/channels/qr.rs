//! QR-code text channel.
//!
//! A QR code is invisible-as-language to a human but decodes to arbitrary text
//! that a downstream tool (or an agent told to "scan the code in the image") will
//! act on. Decode every QR grid in the frame and hand the payloads to the engine.

use image::GrayImage;

/// Decode all QR codes found in a grayscale rendering of the image.
///
/// Barcode formats beyond QR are out of scope for v0.1 (would add a heavy dep);
/// the channel abstraction leaves room to add them without touching callers.
pub fn extract(gray: &GrayImage) -> Vec<String> {
    // rqrr consumes an owned GrayImage.
    let mut prepared = rqrr::PreparedImage::prepare(gray.clone());
    let mut out = Vec::new();
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            if !content.is_empty() {
                out.push(content);
            }
        }
    }
    out
}
