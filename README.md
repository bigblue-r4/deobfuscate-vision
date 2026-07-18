# deobfuscate-vision

[![CI](https://github.com/bigblue-r4/deobfuscate-vision/actions/workflows/ci.yml/badge.svg)](https://github.com/bigblue-r4/deobfuscate-vision/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Image-borne prompt-injection detection — the multimodal companion to
[`deobfuscate`](https://crates.io/crates/deobfuscate).

Attacks against multimodal LLM pipelines hide instructions in the gap between
what a **human perceives** and what a **machine parses**: white-on-white text,
four-pixel fonts, alpha-channel overlays, EXIF comments, QR codes. This crate
extracts every machine-readable text channel from an image and scores each one
with the exact engine you already run on prompts — so a homoglyph or Base64
payload rendered *inside* an image is caught by the same passes that catch it in
text.

```toml
[dependencies]
deobfuscate-vision = "0.1"
```

```rust
use deobfuscate_vision::analyze_image;

let bytes = std::fs::read("upload.png")?;
let report = analyze_image(&bytes)?;
if report.should_block() {
    eprintln!("blocked: {}", report.summary());
}
for ch in &report.channels {
    // Hand extracted text to your Stage-1 injection classifier.
    println!("{:?}: {}", ch.source, ch.extracted);
}
```

## Contents

- [What it detects](#what-it-detects)
- [Scope](#scope)
- [The visibility differential](#the-visibility-differential)
- [OCR is pluggable, not bundled](#ocr-is-pluggable-not-bundled)
- [Hygiene (mitigation)](#hygiene-mitigation)
- [Pipeline placement](#pipeline-placement)
- [License](#license)

## What it detects

| Channel | Extractor | Default |
|---|---|---|
| Metadata injection | EXIF/TIFF comment fields (`UserComment`, `ImageDescription`, `Artist`, …) | ✅ |
| QR / encoded payloads | `rqrr` QR decode → text engine | ✅ |
| Obfuscated rendered text | OCR output → all 19 `deobfuscate` passes | needs OCR |
| **Hidden text** | visibility differential across pixel transforms | needs OCR |

## Scope

Like `deobfuscate`, this crate reports **extraction**, **obfuscation**, and
**hiddenness** — not semantic injection. Whether "ignore previous instructions"
pulled out of an image is actually hostile is a Stage-1 model's call; this
crate's job is to guarantee that text reaches the classifier at all. Every
extracted string is surfaced verbatim on `report.channels`.

## The visibility differential

The image-native analog of `deobfuscate`'s forward/reverse interference score.
OCR the image as a **human** sees it, then OCR a battery of **adversarial**
renderings — contrast stretch, inversion, per-channel planes (including alpha),
2× upscale. Text present *only* in an adversarial rendering is text the sender
hid on purpose. That differential is a far stronger signal than the content of
the text itself, and it scores on the same 0–1 / flag-0.25 / block-0.60 scale.

## OCR is pluggable, not bundled

OCR engines are heavyweight and often need model files or system libraries.
Rather than force that on every dependent, the recognizer is a trait:

```rust
use deobfuscate_vision::{analyze_image_with, TextRecognizer};
use deobfuscate::Config;
use image::GrayImage;

struct MyOcr(/* ocrs / tesseract / cloud handle */);
impl TextRecognizer for MyOcr {
    fn recognize(&self, image: &GrayImage) -> Vec<String> {
        // return recognized lines
        # vec![]
    }
}

let report = analyze_image_with(&bytes, &Config::default(), Some(&MyOcr(/* … */)))?;
```

With **no** recognizer, metadata and QR channels still work and the hidden-text
differential reports `VisibilityScore::Skipped`. Wire in [`ocrs`](https://crates.io/crates/ocrs)
(pure-Rust, no system deps) for a fully self-contained pipeline, or Tesseract via
`leptess` for maximum accuracy.

## Hygiene (mitigation)

`hygiene::sanitize` re-encodes an untrusted image to strip attack channels
without detecting anything — run it before an image reaches a vision model:

```rust
use deobfuscate_vision::hygiene::{sanitize, HygieneOptions};
let clean_png = sanitize(&untrusted_bytes, &HygieneOptions::default())?;
```

The clean decode → optional downscale → metadata-free PNG round-trip drops
EXIF/XMP, quantizes away LSB steganography, and breaks the coherence of
gradient-crafted adversarial perturbations.

## Pipeline placement

```
image bytes
   │
   ├─ hygiene::sanitize  (optional, mutating) ──► clean image ──► vision model
   │
   └─ analyze_image ──► VisionReport ──► your Stage-1 injection classifier
                                          (split-brain-harness, kiss-protocol, …)
```

`analyze_image` is read-only and never mutates the input; `sanitize` is the
mutating mitigation path. Use both.

## License

MIT © bigblue-r4. Companion to the SGAIL / Harborlight security stack.
