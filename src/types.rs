//! Report types for image-channel analysis.
//!
//! Scope mirrors [`deobfuscate`]: this crate reports *extraction*, *obfuscation*,
//! and *hiddenness*. It does **not** decide whether extracted text is a semantic
//! prompt injection — that judgment belongs to a Stage-1 model (e.g. split-brain).
//! The per-channel `extracted` text is surfaced verbatim so a downstream classifier
//! can make that call.

use deobfuscate::NormalizationResult;

/// Where a text channel was pulled out of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum ChannelSource {
    /// Image metadata field (EXIF / XMP / IPTC), e.g. `UserComment`, `ImageDescription`.
    Metadata { field: String },
    /// Decoded QR code or barcode payload.
    QrCode,
    /// Text recognized from the pixels as a human sees them (baseline OCR pass).
    RenderedText,
    /// Text recognized *only* after an adversarial transform (contrast stretch,
    /// channel split, inversion, upscale) — i.e. text the sender hid from a viewer.
    HiddenText { transform: String },
}

/// One extracted text channel plus its text-level analysis.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ChannelResult {
    pub source: ChannelSource,
    /// The raw text extracted from this channel (pre-normalization).
    pub extracted: String,
    /// Result of running the extracted text through [`deobfuscate::analyze`].
    #[cfg_attr(feature = "serde", serde(skip))]
    pub text_analysis: NormalizationResult,
    /// Copy of `text_analysis.obfuscation_score`, retained for serde output.
    pub obfuscation_score: f32,
}

/// Result of the visibility-differential detector (the image-native analog of
/// deobfuscate's forward/reverse interference score).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum VisibilityScore {
    /// No text recognizer was supplied — differential not computed.
    /// Metadata and QR channels are unaffected.
    Skipped,
    /// A recognizer ran. `score` in [0.0, 1.0]: 0.0 = nothing hidden,
    /// 1.0 = substantial text present only in adversarial transforms.
    Scored {
        score: f32,
        /// Transforms under which hidden text surfaced (e.g. `"invert"`, `"alpha_plane"`).
        transforms: Vec<String>,
    },
}

impl VisibilityScore {
    /// Numeric score; `Skipped` counts as 0.0 so it never inflates the composite.
    pub fn value(&self) -> f32 {
        match self {
            VisibilityScore::Skipped => 0.0,
            VisibilityScore::Scored { score, .. } => *score,
        }
    }
}

/// Full image analysis report.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VisionReport {
    /// One entry per extracted text channel, in extraction order.
    pub channels: Vec<ChannelResult>,
    /// Hidden-text differential across pixel transforms.
    pub visibility: VisibilityScore,
    /// Composite image score in [0.0, 1.0] — the max of every channel's
    /// obfuscation score and the visibility score.
    pub image_score: f32,
    /// Flag threshold, inherited from the active [`deobfuscate::Config`].
    pub flag_threshold: f32,
    /// Block threshold, inherited from the active [`deobfuscate::Config`].
    pub block_threshold: f32,
}

impl VisionReport {
    /// True if any text channel was extracted or any hidden text surfaced.
    pub fn has_findings(&self) -> bool {
        !self.channels.is_empty() || self.visibility.value() > 0.0
    }

    /// True if the composite score meets the flag-for-review threshold.
    pub fn should_flag(&self) -> bool {
        self.image_score >= self.flag_threshold
    }

    /// True if the composite score meets the block / stop-and-ask threshold.
    pub fn should_block(&self) -> bool {
        self.image_score >= self.block_threshold
    }

    /// One-line human summary for logs.
    pub fn summary(&self) -> String {
        let hidden = match &self.visibility {
            VisibilityScore::Scored { score, transforms } if *score > 0.0 => {
                format!(", hidden-text {:.2} via {}", score, transforms.join("+"))
            }
            _ => String::new(),
        };
        format!(
            "score {:.2} · {} channel(s){} · {}",
            self.image_score,
            self.channels.len(),
            hidden,
            if self.should_block() {
                "BLOCK"
            } else if self.should_flag() {
                "FLAG"
            } else {
                "clean"
            }
        )
    }
}
