# OpenKeychain PQC v6.0.4-pqc.3

Fixes a real key-generation hang reported by a user — **use this release, not
v6.0.4-pqc.1 or v6.0.4-pqc.2.**

## Fix: key generation hangs forever with a KEM-only master key

If you selected a KEM-only algorithm (ML-KEM-768/1024, composite or
standalone) as your **primary/master key**, the app would let you — every
usage option except "None (subkey binding only)" was disabled for that
combination, and "None" was enough to satisfy the dialog's validation — and
then hang indefinitely at "building key... 0/100" trying to produce a
self-certification signature with a key that has no signing operation at
all (ML-KEM is a pure key-encapsulation algorithm; it cannot sign, and a
primary key must be able to certify).

Fixed by excluding the four KEM-only algorithms from the algorithm picker
whenever it's being used to choose the *primary* key — they remain fully
available as encryption *subkeys*, which is where they belong. Verified live
on-device: the primary-key picker now goes straight from the classical
algorithms to the signing-capable PQC ones (ML-DSA/SLH-DSA), with no way to
select a dead-end configuration. Two new regression tests lock this in.

**If you already hit this hang:** cancel out of key creation, start again,
and make sure your primary key uses a signing algorithm — ML-DSA-65∥Ed25519
(composite, recommended default) or one of the SLH-DSA/standalone ML-DSA
options — then add ML-KEM as an encryption *subkey*, not the primary key.

---

## Also included: v6.0.4-pqc.2's fix

v6.0.4-pqc.1 shared its Android package name with classic upstream
OpenKeychain, so it failed to install for anyone who already had classic
OpenKeychain on their device (different signing key, same package name —
Android blocks this). Fixed in v6.0.4-pqc.2 by renaming the package to
`org.sufficientlysecure.keychain.pqc` and the app label to "OpenKeychain
PQC" — installs as a separate app alongside classic OpenKeychain, no data
loss, no uninstall needed. Still true in this release.

---

## What's new (unchanged since v6.0.4-pqc.1)

First release of the post-quantum cryptography fork, built on upstream
OpenKeychain 6.0.4. A full post-quantum cryptography suite on top of stock
OpenKeychain's classical RSA/ECC/EdDSA support, which remains fully
available and unchanged.

**Standards-track (composite, interoperable) algorithms**, hand-built
against [`draft-ietf-openpgp-pqc`](https://github.com/openpgp-pqc/draft-openpgp-pqc):
- Encryption: ML-KEM-768∥X25519, ML-KEM-1024∥X448
- Signing: ML-DSA-65∥Ed25519, ML-DSA-87∥Ed448, SLH-DSA-SHAKE-128s

**Closed-ecosystem (non-standard) algorithms**, pure PQC with no classical
component, clearly flagged as not interoperating with GnuPG/Sequoia/RNP:
- Encryption: ML-KEM-768, ML-KEM-1024
- Signing: ML-DSA-65, ML-DSA-87

**Full v6 primary-key support**, and **key import** both ways (OpenPGP-wrapped
and raw hex-seed material, the latter gated behind a mandatory security
warning).

## Verification

Every algorithm is wired into the app's real encrypt/decrypt/sign/verify
operations and cross-checked against `draft-ietf-openpgp-pqc`'s own
published test vectors where they exist. Extensively exercised on a real
Android device across every phase of this work, including this exact
release build (R8-minified). Full design history and verification trail:
[`docs/superpowers/specs/2026-07-07-pqc-migration-design.md`](../../docs/superpowers/specs/2026-07-07-pqc-migration-design.md).

## What this is not

**This has not had an external security audit.** The composite and
standalone OpenPGP packet encodings are hand-implemented against a
still-evolving, pre-RFC IETF draft — treat this as a carefully-verified
engineering effort, not a substitute for independent cryptographic review.

## Known follow-up items (tracked, not blocking)

- `HkpKeyserverClient`'s keyserver search-result parser still assumes a
  40-character (v4) fingerprint length; low-impact today since no
  production keyserver serves draft PQC key material yet.
- A couple of test-coverage asymmetries between sibling algorithms where the
  underlying logic is verified correct but not equally regression-guarded.

## Signing

Signed with a dedicated release key (`CN=OpenKeychain PQC, OU=Obsidian
Circuit, O=Dezirae Stark`), package `org.sufficientlysecure.keychain.pqc` —
separate from, and side-by-side installable with, classic OpenKeychain.
