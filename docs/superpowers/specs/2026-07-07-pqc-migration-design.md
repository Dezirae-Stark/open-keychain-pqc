# OpenKeychain PQC Migration — Design

Date: 2026-07-07
Status: Approved for planning

## Goal

Add a full suite of post-quantum cryptography (encryption and signatures) to
OpenKeychain, and support loading PQC keys into the app, while keeping
classical OpenPGP crypto fully available (additive, not a replacement).

Two use cases must both be served:

1. **Standards interop** — exchange keys/messages with other OpenPGP
   implementations as they adopt `draft-ietf-openpgp-pqc` (currently at
   revision -17, pre-RFC as of this writing).
2. **Closed ecosystem** — a "pure PQC," no-classical-component mode for use
   within the operator's own tooling, which does not need to interoperate
   with unmodified GnuPG/Sequoia/RNP installs.

## Current State (as found)

- OpenKeychain's crypto layer: `PgpSecurityConstants.java` (algorithm
  allow-lists), `PgpKeyOperation.java` (key generation/certification),
  `CanonicalizedSecretKey`/`CanonicalizedPublicKey` (encrypt/decrypt/sign/
  verify), `UncachedKeyRing.java` (canonicalization), `KeyFormattingUtils.java`
  (display).
- Crypto is built on a vendored fork of Bouncy Castle at `extern/bouncycastle`,
  pinned at **BC 1.75** (Jan 2024). The fork carries ~20 small, targeted
  OpenPGP-packet-level patches (divert-to-card / GNU-dummy key support,
  opaque-key handling, checksum format, GnuPG-compat quirks) — not a deep
  architectural fork.
- BC 1.75's `core` module has Kyber/Dilithium/SPHINCS+/Falcon engines under
  pre-standardization (round-2/round-3) names. It has **zero PQC support in
  the `pg` (OpenPGP packet) module**.
- Upstream BC (now at 1.84) has added FIPS 203/204 ML-KEM/ML-DSA/SLH-DSA and
  OpenPGP-level PQC integration tracking `draft-ietf-openpgp-pqc`.
- `draft-ietf-openpgp-pqc` defines **composite/hybrid only** for encryption
  (ML-KEM + ECDH) and signatures (ML-DSA + ECDSA/EdDSA); SLH-DSA is the one
  signature scheme allowed standalone. It does not define standalone
  ML-KEM/ML-DSA modes.
- Build tooling is modern enough to not block a BC upgrade: AGP 8.1.4,
  compileSdk 34, Gradle 8.2, Java 17 source/target compatibility. (minSdk 15
  is unrelated to this — pure-Java crypto code is not blocked by it.)
- Algorithm-tag branch points confirmed by grep across the app:
  `CanonicalizedSecretKey`, `PgpKeyOperation`, `PgpSecurityConstants`,
  `UncachedKeyRing`, `KeyFormattingUtils`, plus security-token
  (`EcKeyFormat`/`RsaKeyFormat`/`SecurityTokenUtils`) and SSH auth
  (`SshAuthenticationService`, `SshPublicKey`).
- `Keys.sq` (SQLDelight schema): `algorithm` is a plain `INTEGER NOT NULL`;
  `key_size`/`key_curve_oid` are already generic nullable columns. **No
  schema migration is required.**

## Non-Goals

- **Security token / smartcard support stays classical-only.** No OpenPGP
  card hardware does ML-KEM/ML-DSA math on-card today. PQC secret keys are
  software-only; divert-to-card is disabled for them.
- **SSH authentication stays classical-only.** SSH's own PQC story (hybrid
  KEX at the transport layer) is unrelated to OpenPGP key material. A
  PQC-only key simply doesn't offer itself as an SSH auth identity, rather
  than crashing that code path.

## Architecture

### 1. Dependency layer — rebase vendored BC

`extern/bouncycastle` moves from the 1.75 fork to a current upstream tag
(1.83/1.84 line) carrying ML-KEM, ML-DSA, SLH-DSA, and OpenPGP-packet-level
PQC handling. The ~20 OpenKeychain-specific patches are re-applied as a
rebase on top; some may already be subsumed upstream and can be dropped.

This is done in isolation, verified against OpenKeychain's existing test
suite, **before** any PQC feature code is written on top of it. It is
infrastructure work with genuinely unknown size until attempted — everything
downstream depends on it landing cleanly.

Rejected alternatives:
- *Hand-roll PQC packets on old BC*: keep BC 1.75, add a second BC jar for
  raw PQC primitives, hand-write OpenPGP packet encoding ourselves. Rejected:
  two BC builds both claim the `org.bouncycastle.*` namespace — a real
  classpath collision risk on Android — and hand-writing wire-format-critical
  crypto encoding carries much higher audit risk than reusing BC's own
  scrutinized implementation.
- *Custom non-OpenPGP container*: bespoke PQC key/message format, leave
  classical OpenPGP/BC untouched. Rejected: delivers no standards interop,
  which is a hard requirement here.

### 2. Algorithm & key model

**Composite (interop) algorithms.** Encryption and signing use whatever
public-key algorithm IDs and packet encodings the vendored BC release itself
implements for `draft-ietf-openpgp-pqc`: composite ML-KEM-768/1024∥X25519
(and NIST/Brainpool composite variants if BC includes them) for encryption;
composite ML-DSA-65/87∥Ed25519/Ed448 for signing; SLH-DSA standalone for
signing. Numeric algorithm IDs are taken directly from the pinned BC
version's own encoder/decoder — not hand-derived — so wire format matches
whatever GnuPG/Sequoia build against an equivalent BC version.

**Standalone (closed-ecosystem) algorithms.** No classical component. These
use OpenKeychain-specific algorithm IDs minted from OpenPGP's
Private/Experimental Use range (100–110 in the public-key-algorithm
registry). Clearly surfaced in the UI as *"OpenKeychain PQC (non-standard,
won't interoperate with GnuPG/Sequoia/RNP)"* — this warning must be shown
before the mode can be selected. Implementation reuses BC's own ML-KEM/ML-DSA
key-material marshalling; only the "wrap this key material under our own
private-use algorithm ID, skip the classical half" packet layer is
hand-written. This is the one genuinely new piece of security-critical code
in the whole design and gets a dedicated adversarial review pass (not just
unit coverage) before shipping.

**Security allow-list (`PgpSecurityConstants`).** Every new algorithm ID
(composite and standalone) gets an entry in `getKeySecurityProblem`'s switch
— currently anything unmatched falls through to `UnidentifiedKeyProblem`.
NIST-vetted parameter sets are allowed outright; no bit-strength check is
needed the way ECC curves need curve-allow-listing today.

**Defaults vs. full spread.** Full NIST spread is selectable: ML-DSA-44/65/87,
ML-KEM-512/768/1024, composite or standalone, Ed25519 or Ed448 as the
composite signing partner. Preferred/default selections match the operator's
existing Onna-Bugeisha choices: ML-DSA-65 default signature, ML-KEM-768∥X25519
default encryption, ML-KEM-1024∥X25519 as the "high security" option.

**Key-generation data model.** `SaveKeyringParcel` gains fields for PQC
algorithm, parameter set, and mode (composite/standalone) per subkey.
`CreateKeyFinalFragment` and the key-creation UI gain an algorithm-selection
step (scheme, parameter set, composite-partner curve, non-standard-mode
warning banner). `PgpKeyOperation` gains branches calling BC's composite
key-pair generators (interop path) and the thin OpenKeychain wrapper
(standalone path).

### 3. Crypto operations

`CanonicalizedSecretKey`/`CanonicalizedPublicKey` dispatch on algorithm ID:
- Composite: call through to BC's own composite KEM encapsulation/
  decapsulation (ML-KEM + ECDH via the draft's KDF combiner) and BC's
  composite signer — same shape as today's ECDH/EdDSA branches, new switch
  cases.
- Standalone: call BC's raw ML-KEM/ML-DSA engines directly (bypassing BC's
  composite/bcpg wiring) to build PKESK payloads and signature packets under
  our private-use algorithm ID, via the thin wrapper from §2.

**Unsupported-algorithm handling.** Since the draft is pre-RFC, a foreign
key/message may carry an algorithm ID from a draft revision our pinned BC
doesn't know. Decrypt/verify need an explicit "unsupported PQC algorithm"
result distinct from "corrupt data" or "insecure" — same pattern as today's
`UnidentifiedKeyProblem`, not a crash.

**Canonicalization (`UncachedKeyRing`).** Hard-lists known public-key
algorithm tags (~line 273–282) during canonicalization; anything unlisted is
treated as invalid and stripped on import. New composite and standalone IDs
must join this list or PQC subkeys silently fail to import. Easy to miss —
called out as its own explicit checklist item.

**Storage.** No schema migration needed (`Keys.sq` columns are already
generic). `KeyFormattingUtils` needs a new display convention for PQC keys:
NIST security category (1/3/5) rather than a raw bit-strength number, since
"ML-KEM-768" isn't meaningfully expressed as bits.

### 4. Key import

- **OpenPGP-wrapped PQC keys** (armored blocks with PQC packets, from
  GnuPG/Sequoia/another OpenKeychain-PQC install): falls out of the existing
  import path once the BC rebase and `UncachedKeyRing` allow-list land — same
  "parse a keyring" flow, new packet types understood by the rebased bcpg.
  Must be explicitly verified, not assumed.
- **Raw PQC key material** (e.g. externally-generated key bytes with no
  OpenPGP framing): new import flow constructs a fresh key packet around
  supplied material (creation time, algorithm ID, key bytes), attaches a UID,
  self-certifies — reuses the same packet-assembly path as in-app key
  generation, fed external material instead of BC-generated material. Exact
  input format (raw hex, seed-only vs. expanded key, file vs. paste) is
  deferred to the implementation plan.

## Testing Strategy

- **Rebase regression**: run OpenKeychain's existing unit/instrumented suite
  against the rebased BC before any PQC feature code lands, to isolate
  version-bump regressions from feature regressions. Also run BC's own
  upstream `pg`-module test suite.
- **Round-trip tests per algorithm/parameter combination**: generate → export
  → import → encrypt → decrypt, and sign → verify, for every composite and
  standalone combination exposed. ML-DSA signing is randomized, so these
  compare via `verify()`, not byte-for-byte signature equality.
- **Known-answer tests for the standalone wrapper**: NIST's official
  ML-KEM/ML-DSA test vectors through the private-use-ID packet wrapper —
  exact encode/decode round-trip, fingerprint computation, and negative cases
  (bad signature rejected, tampered ciphertext detected, wrong algorithm ID
  rejected).
- **Canonicalization + legacy regression**: PQC subkeys/binding signatures
  survive canonicalization; every existing classical-algorithm test still
  passes unchanged (concrete check on "keep full legacy support").
- **UI/instrumented**: key-generation algorithm picker, both import flows,
  key-info display formatting.

## Phasing

1. BC rebase + regression baseline (infra only, nothing PQC-visible)
2. Composite encryption + signing for Onna-Bugeisha-consistent defaults
   (ML-KEM-768∥X25519, ML-DSA-65∥Ed25519) — key gen, encrypt/decrypt,
   sign/verify, security-allow-list + canonicalization updates
3. Full NIST parameter spread in the UI + SLH-DSA standalone signing
4. Standalone/closed-ecosystem private-use-ID mode, with its dedicated
   adversarial review pass
5. Key import — OpenPGP-wrapped PQC keys (verify falls out of phase 2/3 for
   free), then raw key-material import
6. UI polish — key-info display conventions, non-standard-mode warnings, docs

## Decisions Log

| Question | Decision |
|---|---|
| Interop scope | Both: standards interop (composite) and closed-ecosystem (standalone) |
| Algorithm spread | Full NIST spread, with Onna-Bugeisha-consistent defaults |
| Legacy crypto | Kept in full — PQC is additive, not a replacement |
| Key import source | Both OpenPGP-wrapped and raw key material; format TBD in implementation plan |
| Architecture | Rebase vendored BC onto current upstream, extend OpenKeychain's own layers |
