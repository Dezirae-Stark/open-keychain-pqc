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

**Both regressions fixed and verified (commit `cdfb783a3`).** Full
`:OpenKeychain:testDebugUnitTest` suite: **212 tests, 211 pass, 1 skip
(pre-existing/unrelated), 0 fail.** Divert-to-card NPE fixed via a placeholder
`PGPPrivateKey` (public-key packet only, private-key-data left `null`) at all
7 affected call sites in `PgpKeyOperation.java` — independently re-verified
to never carry or approximate real secret material, and to be consumed only
by the token-signing builder that already discards that argument. Passphrase
misclassification fixed by widening `PgpDecryptVerifyOperation`'s catch from
`PGPDataValidationException` to `PGPException` (confirmed BC only ever throws
`PGPException` subtypes at that call site — a safe widening, not a mask).
Adversarial review: `readyToMergeIntoMaster: true`, no findings.

**Forward note for Phase 1+:** this fix's version-check placeholder is
coupled to OpenKeychain currently hardcoding OpenPGP v4 signatures
(`PGPSignatureGenerator`'s 1-arg constructor). If composite PQC signing moves
to v6 keys — plausible, since `draft-ietf-openpgp-pqc` is likely to require
v6 — the `publicKeyForVersion` argument at all 7 call sites needs
re-auditing to confirm it still matches the generator's actual version.

## Phase 1 Results: Composite ML-KEM-768∥X25519 Encryption (2026-07-08)

Branch `pqc-phase1-composite-encryption`, built on the merged Phase 0 tip
(local, not pushed).

- Fetched the real `draft-ietf-openpgp-pqc-17` text — datatracker/ietf.org
  are blocked in this environment (HTTP 403), but the IETF OpenPGP WG's own
  GitHub repo (`github.com/openpgp-pqc/draft-openpgp-pqc`) hosts the xml2rfc
  source and is reachable via `raw.githubusercontent.com`. Quoted verbatim,
  not paraphrased. Used the real assigned algorithm ID **35**
  (ML-KEM-768+X25519), not a private-use placeholder — the draft's IANA table
  formally lists it as "TBD(35)" pending registration, but every other
  section uses 35 unambiguously as a MUST-implement value.
- New self-contained crypto module `CompositeMlKem768X25519` implements key
  generation, the exact KDF combiner (SHA3-256 over both KEM shared secrets
  + ciphertext + pubkey + algorithm ID + domain separator — a legitimate
  hybrid combiner, verified not to collapse to only one component's
  strength), PKESK encrypt/decrypt, and RFC 3394 key-wrap directly against
  BC's raw ML-KEM-768/X25519 primitives — bypassing BC's OpenPGP object
  model for the actual cryptography (BC still has none, per the Correction
  above). Three small, precedented patches to the vendored BC fork let its
  packet classes carry algorithm 35's bytes as an opaque blob, mirroring the
  existing `OpaquePublicBCPGKey` pattern.
- **Verification, independently reproduced twice:** the review agent wrote
  its own from-scratch Python OpenPGP packet parser (independent of the
  implementation entirely), pulled the draft repo's own published test
  vectors, and computed the KEK and session-key recovery itself — **matched
  the draft's published values byte-for-byte.** This is the strongest
  verification available short of a live cross-implementation decrypt.
  6/6 new unit tests pass; full suite 218/218.
- **Confirmed blocker (adversarial review caught what two prior passes
  missed):** the crypto core was never wired into the app's real encrypt/
  decrypt path. `CanonicalizedPublicKey.getPubKeyEncryptionGenerator()` and
  `CanonicalizedSecretKey.getCachingDecryptorFactory()` — what
  `PgpSignEncryptOperation`/`PgpDecryptVerifyOperation` actually call —
  still unconditionally build stock BC generators that don't recognize
  algorithm 35. A real encrypt attempt throws
  `IllegalArgumentException: unknown asymmetric algorithm: 35` immediately.
  Both the implementer and first verifier tested only the crypto-core layer
  and missed this. **Decision: fix this wiring before Phase 1 signing
  begins**, and require a real `PgpSignEncryptOperation`/
  `PgpDecryptVerifyOperation` round-trip test (not just a crypto-core test)
  as a standing part of "done" for any future PQC algorithm wiring.
- Full bidirectional interop against gopenpgp/Sequoia-PQC was not attempted
  (they target v6 keys/PKESK; this phase deliberately implements only the
  v3-PKESK/v4-key path the draft permits for algorithm 35 specifically).
  Structural corroboration only (matching field lengths/algorithm ID).

**Wiring fix (2026-07-08):** the app-integration gap is closed.
`CanonicalizedPublicKey`/`CanonicalizedSecretKey` now dispatch algorithm 35
to the composite crypto core through clean, additive branches (no change to
existing RSA/ECDH/X25519/divert-to-card branches or their ordering — verified
by re-running the classical `PgpEncryptDecryptTest` suite unmodified). Two
real bugs surfaced only once a genuine app-level round trip was attempted:
a Robolectric classloader constraint (fixed by splitting the decrypt-side
adapter so no OpenKeychain-namespace class crosses into BC's package), and a
latent vendored-BC defect where an opaque unknown-algorithm public key
embedded *inside* a secret-key packet corrupted the stream on reload —
invisible until a composite key was actually persisted to and reloaded from
a real repository, which no earlier test did. Fixed with a fixed-length read
for algorithm 35 in `PublicKeyPacket.parseKey()`, the same technique BC
already uses for X25519/X448/Ed25519/Ed448. **Note for Phase 1 signing:**
this is a general defect in the fork's opaque-key fallback, not
algorithm-35-specific — any new algorithm ID needing secret-key embedding
will hit it again unless similarly special-cased.

Verification included a negative control: the new real-operation test
(`CompositeMlKem768X25519RealOperationEncryptDecryptTest`) was confirmed to
actually fail with the predicted `unknown algorithm 35` error when the
wiring fix was reverted, then the fix was restored — proving the test would
have caught the bug, not just that it currently passes. Full suite: 219
tests, 0 failures, 1 pre-existing/unrelated skip. Adversarial review:
`readyForSigningPhaseToReuseThisPattern: true`.

**Established pattern for all future PQC algorithm wiring:** crypto core →
wired dispatch in `CanonicalizedPublicKey`/`CanonicalizedSecretKey` → a real
`PgpSignEncryptOperation`/`PgpDecryptVerifyOperation`-level test (not just a
crypto-core test) → a negative control proving that test would fail without
the fix. Composite ML-DSA-65+Ed25519 signing should follow this same
sequence.

## Phase 1 Results: Composite ML-DSA-65+Ed25519 Signing (2026-07-08)

Branch `pqc-phase1-composite-signing` (built on `pqc-phase1-composite-encryption`
in the same worktree), algorithm ID **30**. Unlike encryption's algorithm 35,
the draft gives **no v4 allowance for signing** — composite ML-DSA-65+Ed25519
"MUST be used only with v6 keys ... v6 signatures ... full stop." This phase
correctly built v6 key generation from the start (`PgpKeyOperation`'s first
v6 key path in this codebase), and along the way found and fixed a real
latent bug: v6 secret keys require `USAGE_SHA1` checksum, not the legacy
`USAGE_CHECKSUM` OpenKeychain always used — invisible until this was the
first v6 key ever generated here, correctly scoped to v6 only so the
existing v4 checksum test doesn't regress.

Crypto core, app wiring, a real `PgpSignEncryptOperation`/verify-operation
round-trip test, and a negative control (git-checkout revert → confirmed 5/6
tests fail with the predicted NPE cascade → restore → confirmed clean) were
all done **in the same pass** this time, per the pattern established after
encryption needed a follow-up round. **Verification was the strongest yet:**
cross-checked against the draft's own published test vectors using two
libraries with zero code-sharing with BC or OpenKeychain — Python's
`cryptography` for Ed25519 and pure-Python `dilithium-py` (FIPS-204) for
ML-DSA-65 — both independently confirmed true against the real
foreign-generated signature. Full suite: 225 tests, 0 failures, 1
pre-existing skip.

**Confirmed gap (third adversarial review round, not caught by implementer
or first verifier):** nothing enforces that algorithm 30 is only ever used
with version-6 packets, despite the draft's unconditional v6-only mandate.
`PublicKeyPacket.parseKey()`'s fixed-length read for algorithm 30 doesn't
check the packet version (unlike the generic default branch just below it,
which does); `UncachedKeyRing` canonicalization, `WrappedSignature`, and
`PgpSignatureChecker`'s dispatch all key off algorithm ID alone. Not a
forgery-without-the-key break — the AND-combiner and per-component crypto
are unaffected — but a real version/algorithm-confusion conformance gap: a
foreign or malformed v4-framed algorithm-30 key would parse and canonicalize
successfully today, missing the v6 salt the draft relies on as defense in
depth. **Decision: fix before merge**, same policy as every prior finding
this project.

**Operational note:** the signing-phase agent could not find the
"Established pattern" note above in its worktree checkout and (correctly)
flagged the discrepancy rather than fabricating it — root cause: design-doc
commits have been landing on `master` in the main checkout while feature
work happens on branches in a separate worktree that doesn't automatically
see them. Sync the worktree's docs copy with master before each new phase.

**v6-enforcement fix, closed (2026-07-08).** Fixed at three layers, not just
the two the review named — the implementing agent found and closed two
additional real gaps while implementing the suggested fix rather than
treating the review's named locations as the complete scope: (1) BC-fork
packet parsing — `PublicKeyPacket.parseKey()` **and** `SignaturePacket.
parseSignature()` (the review named only the former; the latter had the
identical hole for signatures specifically) now reject algorithm 30 on any
non-v6 version; (2) `UncachedKeyRing.canonicalize()` defense-in-depth check
for both master keys and subkeys; (3) `PgpKeyOperation`'s subkey-add path now
refuses to bind an algorithm-30 subkey onto a non-v6 master keyring (the
draft's v6-only mandate is about the certificate context, not just one
packet's version byte).

Fourth adversarial review round, fully independent reproduction: traced the
real key-import call chain (`ImportOperation` → `UncachedKeyRing.
decodeFromData` → `PGPObjectFactory` → the fixed parser) to confirm the fix
sits on the one universal parse path, not a side channel; confirmed every DB
write path canonicalizes before persisting, so a non-compliant key can never
reach storage; reproduced the negative controls independently (reverted the
fix at both layers together, confirmed exactly the 3 predicted test failures
in the exact predicted test cases, restored, confirmed green). Full suite:
228 tests, 0 failures, 1 pre-existing skip. **`readyToMergeIntoMaster: true`,
no blockers** — two cosmetic/scoped-out items remain (string-wording i18n
polish; a generic mixed-version-keyring question for *classical* algorithms,
correctly flagged as a separate architectural question, not a defect in this
fix's stated scope).

**Phase 1 is complete: composite ML-KEM-768∥X25519 encryption (algorithm 35)
and composite ML-DSA-65∥Ed25519 signing (algorithm 30), both hand-built
against the real `draft-ietf-openpgp-pqc-17` text, both wired into the app's
real operations, both independently verified against the draft's own
published test vectors, both adversarially reviewed clean.**

## Phase 2 Results: Full NIST Parameter Spread (2026-07-08)

Branch `pqc-phase2-full-nist-spread`, built sequentially in the same
worktree (avoiding conflicting concurrent edits to the shared dispatch
files). Each stage independently confirmed its own v4-vs-v6 version
requirement from the fetched spec text rather than assuming it matched a
sibling algorithm — this mattered, since the requirements are *not* uniform
(only algorithm 35 gets a v4 allowance; everything else here is v6-only).

- **Composite ML-DSA-87∥Ed448 signing (algorithm 31, SHOULD).** Mirrors
  algorithm 30's pattern closely. V6-only, confirmed explicitly (no
  algorithm-31-specific carve-out exists in the text). KAT test against the
  draft's own published vector.
- **Composite ML-KEM-1024∥X448 encryption (algorithm 36, SHOULD).** Mirrors
  algorithm 35's pattern. **V6-only** — confirmed by contrast with the
  preceding sentence's v4-or-v6 allowance for algorithm 35 specifically; not
  assumed to inherit that exception. No KAT available for this one (a
  carried-forward gap from Phase 1: neither ML-KEM algorithm has a published
  test vector to check against, only self-consistent round-trip tests).
- **Standalone SLH-DSA-SHAKE-128s signing (algorithm 32, MAY).** The first
  non-composite PQC algorithm — no classical component, no AND-combiner,
  just SLH-DSA's own native key/signature encoding. V6-only. A real,
  previously-latent bug was found and fixed in the same pass: the vendored
  BC fork's `PGPSignatureGenerator#generate()` had no case for algorithm 32,
  so it fell through to DSA-style MPI encoding and corrupted every
  self-signature made with an SLH-DSA key — caught by actually running the
  tests, not by inspection. SLH-DSA-SHAKE-128f (33) and SLH-DSA-SHAKE-256s
  (34) remain unimplemented, explicitly scoped out rather than
  half-implemented.
- **One workflow run's final Verify/Review stages failed on a transient
  session-usage limit** (not a code or process problem); resumed cleanly
  from cache — the five completed implementation/research stages replayed
  instantly, only the two failed stages re-ran. One stage (SLH-DSA) had
  completed without its automated safety-classifier review being available;
  handled by personally re-running its test suite and inspecting its crypto
  core and the claimed BC-fork bug fix by hand before trusting it — both
  checked out.
- **Full independent re-verification**, including deliberately breaking the
  ML-DSA-87 AND-combiner (`&&` → `||`) to confirm the test suite actually
  catches it (it did — exactly the predicted single failure), byte-identical
  restores confirmed via `md5sum`, and the pre-existing 3-failure bcpg
  baseline reconfirmed unaffected via a disposable worktree at the
  pre-Phase-2 commit. Full suite: 257 tests, 0 failures, 1 pre-existing
  skip (+29 over Phase 1's 228, exactly matching the three additions' new
  test counts). `readyToMergeIntoMaster: true`, no blockers — two disclosed
  minor test-coverage gaps (no ML-KEM-1024 KAT; no permanent regression
  test for the v4-master/algorithm-31-or-32-subkey-add rejection path),
  both consistent with existing project-wide precedent, tracked as
  follow-ups rather than blockers.

## Phase 4 Results: Standalone (Closed-Ecosystem) PQC Mode (2026-07-08)

Branch `pqc-phase4-standalone-mode`, built on merged Phase 2. Pure ML-KEM-768
(algorithm 100), ML-KEM-1024 (101), ML-DSA-65 (102), and ML-DSA-87 (103) —
no classical component, no combiner — using OpenPGP's private-use range
(`EXPERIMENTAL_1`-`4`). **Deliberately non-standard: these will not
interoperate with GnuPG, Sequoia, RNP, or any other OpenPGP implementation.**
`EXPERIMENTAL_5`-`11` left explicitly unassigned/reserved, not silently
half-implemented.

Since no spec governs this range, the implementing agent had to make and
document real design calls rather than transcribe a spec: algorithm ID
ordering (grouped by primitive — KEM pair then DSA pair — rather than
mirroring the composite block's IANA-artifact ordering), and critically,
**KEK derivation for the KEM pair still runs the raw ML-KEM shared secret
through a domain-separated SHA3-256 hash** (citing NIST SP 800-56C's
guidance against using a raw KEM shared secret directly) **with a new,
distinct domain separator** (`"OpenKeychainStandaloneKEMKDFv1"`) rather than
reusing the composite path's `"OpenPGPCompositeKDFv1"` — deliberately, to
prevent domain-separator collision between two different constructions.
Version requirement: v6-only for all four (this codebase's own choice, made
explicitly rather than defaulted), enforced via the same three-layer
defense-in-depth pattern as every other v6-only algorithm here.

Full app wiring done in one pass per algorithm pair, per the established
rule. One real bug caught by an actual negative-control test run, not
inspection: a `sed`-generated test file had a case-sensitivity typo
(`STANDALONE_ML_KEM_768` instead of `_1024`), caught because the test
non-vacuously checked the on-wire PKESK algorithm tag. Full suite: 294
tests, 0 failures, 1 pre-existing skip (+37 over Phase 2's 257).
`readyToMergeIntoMaster: true` — one disclosed minor gap (no dedicated
permanent version-enforcement regression test for algorithm 101 specifically,
though the verify pass independently confirmed the underlying enforcement
is genuinely active via a scratch test), and a note that the design doc's
"warning shown before the mode can be selected" requirement is necessarily
unmet — because **no PQC algorithm from any phase (composite or standalone)
is yet selectable from any UI**, consistent with this project's phasing
(UI is Phase 6, not yet started). The data-model flag
(`isNonStandardClosedEcosystemPqc`) and display strings are genuinely
present and correctly labeled, ready for the UI phase to consume.

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
