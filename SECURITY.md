# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/bigblue-r4/deobfuscate-vision/security/advisories/new)
— do **not** open a public issue for anything exploitable. Coordinated
disclosure preferred; reporters are credited unless they ask otherwise.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x | ✅ current development line |

**0.x — the API is not yet stable**, and this crate is not published to
crates.io. Depend on it by git revision and pin it.

## Threat model and scope

This crate extracts every machine-readable **text channel** from an image and
scores each with the [`deobfuscate`](https://crates.io/crates/deobfuscate)
engine. The attack it exists for is the gap between what a human perceives in
an image and what a multimodal model parses out of it.

In scope as a security bug:

- A text channel this crate claims to extract that is silently dropped.
- A panic, hang, or unbounded allocation on a malformed or hostile image —
  this crate parses untrusted binary input and that is its sharpest edge.
- An extracted channel that is not forwarded to `deobfuscate` for scoring.

### What is covered by default, and what is not

**`analyze_image()` with no recognizer covers metadata and QR only.** The
`RenderedText` and `HiddenText` channels — the visibility-differential pass
that catches white-on-white and four-pixel-font payloads — require a
[`TextRecognizer`](src/visibility.rs) supplied by you. OCR is a pluggable trait
by design, because engines are heavyweight and need model files; the cost is
that **a deployment without a recognizer is blind to text rendered in pixels**
and will report clean on an image whose only payload is drawn rather than
stored. Check `report.channels` for what was actually inspected rather than
assuming full coverage.

Also out of scope:

- Adversarial perturbation of a model's vision encoder — this crate reads text,
  not embeddings.
- Steganographic payloads in channels no OCR or parser surfaces (LSB bitplanes,
  ancillary chunks).
- Deciding policy. Scores are advisory; blocking belongs to the caller.

## Assurance

| Property | Mechanism |
|----------|-----------|
| Behaviour pinned | unit tests + a fixture bench over generated adversarial images, on every push and PR |
| No lint regressions | `cargo clippy --all-features -- -D warnings` in CI |
| Text-layer scoring | delegated entirely to `deobfuscate`, which carries its own fuzz targets and corpus gates |

### Parser exposure

Image decoding is the untrusted-input surface: `image`, `kamadak-exif` and
`rqrr` all parse attacker-controlled bytes. The `image` decoder set is held to
`default-features = false` plus an explicit format list (`png`, `jpeg`, `gif`,
`webp`, `bmp`) so that formats nobody enabled cannot become an attack surface.
Advisories against any of these three crates should be treated as affecting
this one; Dependabot watches them.
