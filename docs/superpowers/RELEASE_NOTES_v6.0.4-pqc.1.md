# OpenKeychain PQC v6.0.4-pqc.1

First release of the post-quantum cryptography fork, built on upstream
OpenKeychain 6.0.4.

## What's new

A full post-quantum cryptography suite has been added on top of stock
OpenKeychain's classical RSA/ECC/EdDSA support, which remains fully
available and unchanged.

**Standards-track (composite, interoperable) algorithms**, hand-built
against [`draft-ietf-openpgp-pqc`](https://github.com/openpgp-pqc/draft-openpgp-pqc)
since no OpenPGP library — including upstream Bouncy Castle — has
OpenPGP-packet-level PQC support to inherit from:
- Encryption: ML-KEM-768∥X25519, ML-KEM-1024∥X448
- Signing: ML-DSA-65∥Ed25519, ML-DSA-87∥Ed448
- Signing (standalone, hash-based): SLH-DSA-SHAKE-128s

**Closed-ecosystem (non-standard) algorithms**, pure PQC with no classical
component, using OpenPGP's private-use algorithm ID range — clearly flagged
everywhere they appear as not interoperating with GnuPG/Sequoia/RNP or any
other OpenPGP software:
- Encryption: ML-KEM-768, ML-KEM-1024
- Signing: ML-DSA-65, ML-DSA-87

**Full support for v6 primary keys**, so any of the above can actually serve
as your key's primary identity, not just a subkey — including a security-
critical version-consistency fix so a classical subkey under a v6 PQC
master key doesn't end up silently mismatched.

**Key import**, both directions:
- OpenPGP-wrapped PQC keys (armored key blocks) import through the normal
  Import Keys flow, same as any other key.
- Raw PQC key material (hex-encoded seed + algorithm) can be imported
  directly — useful for deterministic key recovery from a backed-up seed.
  This is clearly gated behind a mandatory security warning, since supplying
  your own key material bypasses the app's own randomness entirely.

**UI**: all of the above is reachable from the normal key-creation and
subkey-add screens, with algorithm descriptions, security-category labels,
and interop warnings shown inline.

## Verification

Every algorithm is wired into the app's real encrypt/decrypt/sign/verify
operations — not just isolated crypto-core unit tests — and cross-checked
against `draft-ietf-openpgp-pqc`'s own published test vectors where they
exist; where they don't (the two ML-KEM composite algorithms), correctness
was independently re-derived from Bouncy Castle's own primitive classes.
Extensively exercised on a real Android emulator across every phase of this
work: key generation, viewing, sharing/QR export, import, and sign+verify
round trips — including this exact release build (R8-minified, not just a
debug build), which was installed and driven through composite PQC key
generation before publishing.

Full design history, every decision made and why, and the complete
verification trail: [`docs/superpowers/specs/2026-07-07-pqc-migration-design.md`](../../docs/superpowers/specs/2026-07-07-pqc-migration-design.md).

## What this is not

**This has not had an external security audit.** The composite and
standalone OpenPGP packet encodings are hand-implemented against a
still-evolving, pre-RFC IETF draft (`draft-ietf-openpgp-pqc`, currently
around revision -17) — the wire format could still change before the draft
becomes an RFC. Treat this as a serious, carefully-verified engineering
effort, not as a substitute for independent cryptographic review.

## Known follow-up items (tracked, not blocking)

- No validation prevents selecting an encryption-only (KEM) algorithm as a
  signing-capable master/certifying key — would fail late, at signature
  time, rather than being rejected upfront.
- `HkpKeyserverClient`'s keyserver search-result parser still assumes a
  40-character (v4) fingerprint length; a v6 fingerprint from a keyserver
  would be silently skipped. Low-impact today since no production keyserver
  serves draft PQC key material yet.
- A couple of test-coverage asymmetries between sibling algorithms (e.g. one
  parameter set has a dedicated regression test another doesn't) — the
  underlying logic is verified correct in both cases, just not equally
  guarded against future regressions.

## Signing

This release is signed with a new, dedicated release key
(`CN=OpenKeychain PQC, OU=Obsidian Circuit, O=Dezirae Stark`), not the
upstream OpenKeychain signing key. It will not upgrade-in-place over an
existing OpenKeychain install signed with a different key.
