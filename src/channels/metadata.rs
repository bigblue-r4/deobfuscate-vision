//! Metadata text channel — EXIF / TIFF comment fields.
//!
//! Attackers stash instructions in `UserComment`, `ImageDescription`, `XPComment`,
//! `Artist`, `Copyright`, or `Software` where a human never looks but a
//! metadata-ingesting pipeline (or a multimodal model given the raw file) will.

use std::io::Cursor;

/// Extract every text-bearing metadata field as `(field_name, value)`.
///
/// Returns an empty vec when the image has no parseable EXIF container.
pub fn extract(bytes: &[u8]) -> Vec<(String, String)> {
    let reader = exif::Reader::new();
    let mut cursor = Cursor::new(bytes);
    let exif = match reader.read_from_container(&mut cursor) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for field in exif.fields() {
        // Use the RAW value, not `display_value()`. The display form wraps
        // strings in quotes, escapes inner quotes, and renders non-ASCII bytes
        // as `\xNN` — all of which corrupt a payload before it reaches the text
        // engine (a `b64.decode("…")` marker breaks, fullwidth homoglyphs never
        // arrive as codepoints). Decoding the raw bytes as UTF-8 preserves the
        // attacker's actual payload verbatim.
        let value = match raw_text(&field.value) {
            Some(v) => v,
            None => continue,
        };
        if is_texty(&value) {
            out.push((field.tag.to_string(), value));
        }
    }
    out
}

/// Decode the raw bytes of a text-bearing EXIF value as UTF-8 (lossy).
///
/// Handles `Ascii` (comment/description fields) and `Undefined` (the raw byte
/// container `UserComment` uses, which carries an 8-byte encoding prefix we skip
/// when it is the standard `ASCII\0\0\0` / `UNICODE\0` marker).
fn raw_text(value: &exif::Value) -> Option<String> {
    match value {
        exif::Value::Ascii(components) => {
            let joined: Vec<u8> = components.join(&b' ');
            Some(String::from_utf8_lossy(&joined).trim_end_matches('\0').to_string())
        }
        exif::Value::Undefined(bytes, _) => {
            let payload = strip_comment_prefix(bytes);
            Some(String::from_utf8_lossy(payload).trim_end_matches('\0').to_string())
        }
        _ => None,
    }
}

/// EXIF `UserComment` prefixes its text with an 8-byte character-code marker
/// (`ASCII\0\0\0`, `UNICODE\0`, `JIS\0\0\0\0\0`, or all-zero for undefined).
/// Strip it when present so only the payload reaches the engine.
fn strip_comment_prefix(bytes: &[u8]) -> &[u8] {
    const MARKERS: [&[u8; 8]; 4] = [
        b"ASCII\0\0\0",
        b"UNICODE\0",
        b"JIS\0\0\0\0\0",
        b"\0\0\0\0\0\0\0\0",
    ];
    if bytes.len() >= 8 && MARKERS.iter().any(|m| &bytes[..8] == m.as_slice()) {
        &bytes[8..]
    } else {
        bytes
    }
}

/// A metadata value is worth analyzing only if it carries actual language:
/// at least three alphabetic characters. This skips the flood of numeric EXIF
/// fields (exposure, focal length, timestamps) that are never injection carriers.
fn is_texty(value: &str) -> bool {
    value.chars().filter(|c| c.is_alphabetic()).count() >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_exif_is_empty() {
        assert!(extract(b"not an image").is_empty());
    }

    #[test]
    fn texty_filter() {
        assert!(is_texty("ignore previous instructions"));
        assert!(!is_texty("1/250"));
        assert!(!is_texty("55")); // focal length, no letters
    }
}
