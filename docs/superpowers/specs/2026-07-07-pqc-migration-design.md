# OpenKeychain PQC Migration — Design

Date: 2026-07-07 (revised same day, post Phase-0)
Status: Approved for planning; architecture revised after Phase-0 findings invalidated a core premise

## Correction (post Phase-0, same day)

The original version of this doc assumed upstream Bouncy Castle had already
added OpenPGP-packet-level PQC support (composite ML-KEM/ML-DSA, standalone
SLH-DSA) to track `draft-ietf-openpgp-pqc`, based on an imprecise web search.
**This is false.** Direct source-tree inspection of bc-java (every release
1.75→1.84, plus current `main`) found zero PQC-related classes anywhere in
`org.bouncycastle.bcpg`/`org.bouncycastle.openpgp` — no `MLKEM*`/`MLDSA*`/
`SLHDSA*`/`Composite*` packet classes, no PQC entries in
`PublicKeyAlgorithmTags`. BC's real, current PQC work (ML-KEM/ML-DSA/SLH-DSA,
genuinely present) targets CMS, X.509/PKIX, and TLS — not OpenPGP. No OpenPGP
library has ready-made composite/standalone PQC packet support to inherit.

This changes the architecture materially: §2 and §3 below are revised so that
**both composite and standalone PQC packet handling are hand-built**, on top
of BC's real (non-OpenPGP) ML-KEM/ML-DSA/SLH-DSA primitive engines, against
the `draft-ietf-openpgp-pqc` wire format directly — not inherited from a
scrutinized upstream implementation. Correctness is anchored by round-trip
interop testing against another draft implementation (GopenPGP or
Sequoia-PQC, which do implement it), not by reusing BC's own test coverage.
This was an explicit, informed decision (see Decisions Log) made after the
tradeoff was made visible, not a default.

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
- Upstream BC (1.84, the latest tagged release; current `main` pre-bumped to
  1.85 with no tag/artifact yet) has added real FIPS 203/204 ML-KEM/ML-DSA/
  SLH-DSA primitives, but **only for CMS/X.509/TLS — verified, by direct
  source-tree inspection, to have zero OpenPGP-packet-level PQC support**
  (see Correction above). The primitive engines are real and reusable; the
  OpenPGP wire-format binding is not.
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
- *Custom non-OpenPGP container*: bespoke PQC key/message format, leave
  classical OpenPGP/BC untouched. Rejected: delivers no standards interop,
  which is a hard requirement here.

**Post Phase-0 note:** the original rejection of "hand-roll PQC packets" rested
on avoiding a *second* BC build coexisting with the vendored fork (a real
`org.bouncycastle.*` classpath collision risk). That's moot now: there is only
ever one BC version in the app (the rebased 1.84 fork). But since no BC
version has OpenPGP-packet PQC support to inherit (see Correction), the
*conclusion* of that rejected option — hand-writing OpenPGP packet encoding
for PQC — is now unavoidable regardless of which BC version is used. The
namespace-collision risk that motivated rejecting it is gone; the
wire-format-correctness risk it also carried is not, and is now taken on
deliberately, scoped to both composite and standalone modes, with real
cross-implementation interop testing as the verification anchor instead of
inherited BC test coverage.

### 2. Algorithm & key model

**Composite (interop) algorithms.** No OpenPGP library defines these for us
to inherit (see Correction), so composite ML-KEM-768/1024∥X25519 (encryption)
and composite ML-DSA-65/87∥Ed25519/Ed448 (signing) are hand-built: numeric
algorithm IDs and packet encoding taken directly from the
`draft-ietf-openpgp-pqc` spec text (currently believed to be around revision
-17, but the exact revision and its text must be fetched and read directly
before implementation — not assumed from search snippets, several of which
in this project have already turned out to be imprecise), reusing BC's real
ML-KEM/ML-DSA primitive engines (from `core`, the same ones CMS uses) for the
actual lattice math, and the draft's KDF combiner logic for the composite
"hybrid" combination with X25519/Ed25519. This is now the single largest,
highest-review-priority piece of new code in the whole project — not a small
wrapper — and its correctness is anchored by round-tripping keys/messages
against another draft implementation (GopenPGP or Sequoia-PQC), since there's
no inherited test suite to lean on.

**Standalone (closed-ecosystem) algorithms.** No classical component. These
use OpenKeychain-specific algorithm IDs minted from OpenPGP's
Private/Experimental Use range (100–110 in the public-key-algorithm
registry) — confirmed reachable from application code for raw packet
encode/decode via `PublicKeyPacket`'s public constructor, but confirmed
*not* reachable for actual signing/encryption dispatch (`PublicKeyUtils`'s
`isSigningAlgorithm()`/`isEncryptionAlgorithm()` and `PublicKeyPacket`'s
decode-side `parseKey()` are hardcoded switches with no extension point, so
wiring a 100–110 algorithm into real crypto operations requires patching
those switches in the vendored fork, not just subclassing from OpenKeychain's
own code). Clearly surfaced in the UI as *"OpenKeychain PQC (non-standard,
won't interoperate with GnuPG/Sequoia/RNP)"* — this warning must be shown
before the mode can be selected. Reuses BC's own ML-KEM/ML-DSA key-material
marshalling for the actual key bytes; the packet-dispatch wiring in the fork
plus the "no classical component" packet shape are hand-written. Gets the
same dedicated adversarial review pass as the composite path.

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
- Composite: call BC's raw ML-KEM engine for encapsulation/decapsulation and
  BC's raw ML-DSA engine for sign/verify (both from `core`), combined with
  X25519/Ed25519 per the draft's own KDF-combiner and encoding rules —
  implemented in OpenKeychain/the fork, since BC has no composite OpenPGP
  wiring to call into. Same dispatch shape as today's ECDH/EdDSA branches,
  new switch cases, but new logic behind them rather than a passthrough.
- Standalone: call BC's raw ML-KEM/ML-DSA engines directly to build PKESK
  payloads and signature packets under our private-use algorithm ID, via the
  packet-dispatch patch + wrapper from §2.

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
- **Known-answer tests against NIST's own ML-KEM/ML-DSA/SLH-DSA vectors**,
  applied at the primitive layer (BC's `core` engines) before any OpenPGP
  packet framing is involved, to separate "is the underlying crypto right"
  from "is our packet encoding right."
- **Cross-implementation interop tests** — since no packet-layer code is
  inherited from BC, this is now the primary correctness anchor for the
  composite (and, where feasible, standalone) packet layer: round-trip a
  generated key/message against an independent `draft-ietf-openpgp-pqc`
  implementation (GopenPGP or Sequoia-PQC), both directions (their key into
  our app, our key into theirs), not just self-round-trip.
- **Round-trip tests per algorithm/parameter combination**: generate → export
  → import → encrypt → decrypt, and sign → verify, for every composite and
  standalone combination exposed. ML-DSA signing is randomized, so these
  compare via `verify()`, not byte-for-byte signature equality.
- **Canonicalization + legacy regression**: PQC subkeys/binding signatures
  survive canonicalization; every existing classical-algorithm test still
  passes unchanged (concrete check on "keep full legacy support").
- **UI/instrumented**: key-generation algorithm picker, both import flows,
  key-info display formatting.

## Phase 0 Results (2026-07-07)

Executed via two background workflows (`wf_620675b1-c5d`, `wf_5adbdc27-a8f`)
in an isolated worktree; nothing pushed or merged to master.

- `extern/bouncycastle` rebased from BC 1.75 (`a76cb19f7`) onto bcgit/bc-java
  tag `r1rv84` (BC 1.84, the latest actual tagged release — confirmed via
  `git ls-remote` and Maven Central metadata; `main` is pre-bumped to 1.85 but
  unreleased). Of 21 OpenKeychain-specific patches: 11 cherry-picked clean,
  9 reimplemented against the restructured 1.84 codebase, 1 (`361fbde53`,
  two-byte checksum) confirmed genuinely subsumed by upstream's own current
  logic and correctly dropped.
- One patch (`395e6c314`, GPG4USB CRCRLF armor tolerance) initially caused a
  confirmed regression when dropped (`ArmoredInputStreamTest` NPE, verified
  by direct reproduction) — fixed properly via a shared pushback-buffer
  refactor across `ArmoredInputStream`'s read call sites, verified against
  both OpenKeychain's own fixture and bc-java's `crOnlySignedMessage` case.
- Picked up real upstream CVE fixes along the way (unbounded PGP AEAD chunk
  size resource exhaustion, composite-verifier hardening).
- Two pre-existing, BC-unrelated app-build blockers were found and fixed:
  five dependencies pinned to versions that only ever lived on the now-dead
  JCenter, and `eu.davidea:flexible-adapter:5.1.0`'s Java-21 bytecode
  breaking this environment's Jetifier. Both predate this project and would
  have blocked any build attempt regardless of PQC work.
- `780165c13` (the `isMasterKey()` strict-semantics divergence, intentionally
  kept) breaks 4 tests in bc-java's own suite, including 3 in its newer
  (post-1.81) `org.bouncycastle.openpgp.api.*` surface — currently inert
  since OpenKeychain doesn't use that surface, but a landmine if any future
  PQC code reaches for `OpenPGPKeyGenerator`/`OpenPGPCertificate`/
  `OpenPGPKeyEditor` instead of the legacy `PGPPublicKey`/`PGPSecretKey`
  classes OpenKeychain uses today.
- **The upstream-PQC-support premise this design originally rested on was
  found to be false** — see Correction at the top of this document. This is
  the load-bearing Phase 0 finding; everything in §2/§3 was revised as a
  result.

### Phase 0 close-out (same day)

Branch `pqc-migration-phase0-crcrlf-and-build-fixes` in the outer repo
(local, in the worktree, not master, not pushed):

- CRCRLF armor regression fixed properly (shared pushback buffer across
  `ArmoredInputStream`'s read call sites), independently re-verified
  including a mixed-stream interaction case and an EOF-truncation edge case.
- All 5 dead-JCenter/Jetifier build blockers fixed (see dependency list in
  commit `3c5ffa91f`); `:OpenKeychain:compileDebugJavaWithJavac` now succeeds
  and the app's own test suite runs end-to-end for the first time in this
  environment: 212 tests, 209 pass, 1 skipped.
- Running the suite end-to-end for the first time surfaced two **real**
  BC-1.84-vs-app-code regressions (not test artifacts): (1) BC 1.84's
  `PGPSignatureGenerator.init()` added a version check that NPEs on
  OpenKeychain's divert-to-card (security-token) subkey-signing flow, which
  intentionally passes a null private key; (2) BC 1.84 no longer reliably
  throws the exception type `PgpDecryptVerifyOperation` expects to classify a
  wrong symmetric passphrase, making that error message unreliable
  (order-dependent in testing). **Decision: fix both before touching
  master** (tracked in a follow-up workflow, not deferred as known issues).
- SignaturePacket unsupported-version handling: restored to OpenKeychain's
  original fail-loud `IOException` (reject outright) over BC's newer
  silent-skip behavior. **Ratified by operator, 2026-07-07**: keep fail-loud.
- `PGPKeyRingTest#testSubKeyCreation` / `OpenPGPCertificateTest` failures in
  bc-java's own `pg` test suite are a pre-existing, decade-old conflict
  between OpenKeychain's `isMasterKey()` divergence and a 2022 upstream test
  addition — confirmed present identically in the pre-rebase 1.77 fork, never
  previously caught because this test module was never run in CI. Not a new
  regression; left as-is, `:extern:bouncycastle:pg:test` will never show a
  literal 31/31 without reverting that decade-old divergence.

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
| PQC packet strategy (post Phase-0) | Hand-build the OpenPGP PQC packet layer (composite + standalone) on BC's real primitives, verified via cross-implementation interop testing, rather than deferring standards interop or pausing |
| CRCRLF regression | Fixed properly (pushback-buffer refactor) rather than accepted as a dropped GPG4USB compatibility loss |
| SignaturePacket unsupported-version handling | Fail-loud (`IOException`, reject outright) confirmed over BC's newer silent-skip behavior |
| BC-1.84 regressions (divert-to-card NPE, passphrase-classification flakiness) | Fix both before touching master, not deferred as known issues |
