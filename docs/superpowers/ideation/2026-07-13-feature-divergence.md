# OpenKeychain PQC — Feature Divergence Session

**Date:** 2026-07-13
**Skill:** divergent-invention (collaborative mode)
**Status:** Phase 2/3 (generation + cross-pollination) — raw idea space, no judgment applied yet

## The dream

OpenKeychain PQC stops being "a key manager with post-quantum algorithms bolted on"
and becomes a **foundational trust/identity layer for the post-quantum era** —
something other apps, devices, and even other people's workflows build on top of,
useful across a wide range of applications, not just OpenPGP specialists.

**Existing systems in the operator's portfolio available for cross-pollination:**
Onna-Bugeisha (Tor-only BTC wallet, ML-DSA-65 signatures, Whirlpool CoinJoin,
BTC-XMR atomic swaps), QWAMOS/VALKYRJA (ARM64 hypervisor hardware, HNCP,
IOMMU/EL2/EL3 compartmentation, kill switches, glass photonic QRNG roadmap),
Cryptanalytic Research (algebraic attacks on ECC/PQC), Cytherea (six-layer
organism architecture, soft-guardrail autonomy), Mindforge (single-file browser
tools, session-log JSON schema).

**True constraints treated as design material, not walls:** PQC keys/signatures
are much larger than classical (ML-DSA-65 sigs ~3.3KB, SLH-DSA sigs can run
tens of KB); lattice/hash-based hardness assumptions have no unconditional
proof; `draft-ietf-openpgp-pqc` is still evolving; mobile battery/bandwidth/
storage are real; Android's permission and background-execution model is real;
QR code and NFC payload sizes are bounded.

---

## Lens 1: Biological / evolutionary

**Immune-system key revocation.** Model compromised-key propagation on
adaptive immunity: a "memory cell" layer records the *pattern* of a past
compromise (which subkey type, which usage flag, which import path), so that
if a structurally similar key later appears, the app flags it pre-emptively
before any CRL/keyserver round-trip. Structural transfer: primary vs. adaptive
immunity — fast pattern-matched response vs. slow first-encounter response.

**Swarm quorum-sensing for social recovery.** Borrow bacterial quorum sensing
(cells only commit to a group behavior once a diffusible signal crosses a
concentration threshold) for **Shamir-style key recovery among trusted
contacts**: each holder of a key share broadcasts a low-bandwidth "I'm alive
and willing" ping; reconstruction only triggers once the threshold count is
sensed, not the moment shares happen to be collected. Reduces premature/
partial reconstruction attempts.

**Mycelial trust-network routing.** Mycelium routes nutrients toward whichever
connected node signals need, redistributing along the path of least
resistance. Map onto **web-of-trust path discovery**: instead of a static
signature graph, the app continuously "probes" which of your certifiers are
still reachable/responsive (like nutrient flow) and recommends the
freshest live trust path for a given contact, not just the shortest graph-
theoretic one.

**Metabolic key-rotation budget.** Cells allocate a finite ATP budget across
competing processes. Give each identity a "cryptographic metabolism budget" —
a soft, user-tunable rate at which subkeys are allowed to rotate/reissue,
throttled automatically under low-battery or low-connectivity conditions
(rotation deferred, not blocked), so key hygiene doesn't silently drain a
travelling user's phone.

**Symbiosis-based hardware pairing.** Lichen is a stable symbiosis between
fungus and alga, neither able to do what the composite does alone. Model
**phone + hardware security token pairing** as an explicit symbiotic contract
object: the phone declares what it needs from the token (signing ops,
storage) and vice versa (a heartbeat/liveness check), and the UI visualizes
the *health of the symbiosis*, not just "token connected: yes/no."

**Morphogenetic UI that grows with key complexity.** Morphogenesis: simple
local rules produce complex global form (e.g., Turing patterns). A user
starting with one classical Ed25519 key sees a minimal UI; as they add PQC
composite subkeys, security-token bindings, and multiple identities, the UI
*grows new structure* (tabs, panels) governed by the same small rule set
throughout, rather than jumping to "advanced mode" as a discrete toggle.

**Ecosystem-style key diversity scoring.** Monocultures are fragile;
ecosystems favor diversity because a single pathogen can't wipe out every
species at once. Add a **"cryptographic biodiversity" score** to a user's
overall trust graph: if every contact you trust uses the same single PQC
parameter set, flag it — a future break in that one primitive is
correlated risk across your whole graph, exactly like a monoculture crop
failure. [speculative: assumes some future PQC primitives break
independently of others, which is the working assumption of "hedge with
multiple hard problems" but not proven]

**Circadian-rhythm passphrase caching.** Body clocks desynchronize gradually
under jet lag rather than snapping instantly. Instead of a hard passphrase-
cache timeout, let the cache "desynchronize" gradually — confidence in the
cached passphrase decays smoothly, and the app asks for lighter
reconfirmation (fingerprint) before the full timeout, then full
reauthentication after, mirroring how trust actually degrades with time
away from the device.

**Pheromone-trail UX for frequently used identities.** Ants reinforce paths
by repeated pheromone deposit; unused paths evaporate. Let the identity/key
picker reorder itself based on a decaying-reinforcement usage signal (not
just last-used timestamp) — heavily used signing identities become
structurally "closer" (fewer taps) over time, and cold ones recede, without
the user ever managing a list manually.

**Molting / hard boundary key generations.** Arthropods periodically shed
an exoskeleton entirely rather than patching it. Offer a formal **"molt"**
key-lifecycle action distinct from ordinary rotation: a one-tap, clearly
irreversible generation boundary that revokes the *entire* old primary key
graph and starts a fresh v6 primary with a signed "molt certificate" linking
old-self to new-self cryptographically, for users who suspect broad (not
single-subkey) compromise.

**Autophagy — self-cleaning of stale key material.** Cells recycle their own
damaged components via autophagy under stress signals (e.g., low nutrients).
Add a background low-priority process that, under user-approved policy,
identifies and offers to purge expired/revoked/orphaned key material
(old subkeys, superseded imports) to reclaim storage, triggered opportunistically
like autophagy is triggered by cellular stress (low storage) rather than on a
fixed schedule.

### Second independent pass (biological lens, run in parallel)

**Immune memory for compromised keys (T-cell recall).** Adaptive immunity
remembers prior pathogens via memory cells for faster future response. The
app maintains a local "memory" of fingerprint/algorithm patterns from keys
previously flagged bad (weak curves, broken RNGs, revoked CAs) and
pre-emptively warns on structurally similar new keys, even before any
keyserver revocation propagates. Distinct from the Lens-1 "immune-system key
revocation" entry above in that this one keys off structural *pattern*
similarity across unrelated keys, not just re-encountering the same key.

**Symbiotic co-signing (lichen: fungus + alga).** Lichen is literally two
organisms functioning as one. Let two devices/keys (e.g., phone + hardware
token) form a persistent symbiotic pair where neither can sign alone, but the
composite operation is faster/cheaper than a general threshold scheme — a
minimal, purpose-built 2-of-2 "obligate symbiont" signing mode distinct from
full threshold sig.

**Morphogenetic key UI (positional gradients in embryo development).**
Morphogen concentration gradients tell cells "where" they are in a body plan.
Render the key list as a spatial gradient — keys visually cluster/position by
trust-gradient, freshness-gradient, algorithm-strength-gradient — instead of
a flat sorted list. [speculative: UX value unproven, a visualization
hypothesis]

**Ecosystem succession for algorithm deprecation (forest succession
stages).** Ecosystems move through pioneer→climax species as conditions
change. Show each key's algorithm mix as a "succession stage"
(classical→composite→standalone-PQC) and the whole keyring's position on a
pioneer-to-climax gradient, gently favoring forward succession opportunistically
rather than forcing migration.

**Autoimmune guard (self/non-self discrimination, MHC).** Immune systems
distinguish self from non-self via MHC presentation. Before signing/
certifying any foreign key, run a "self-recognition" check comparing the
candidate's provenance/algorithm-mix against the user's own keyring's
established baseline, flagging foreign keys that deviate structurally (e.g.
the first standalone-PQC key you've ever seen from an otherwise all-composite
contact) as needing extra scrutiny.

**Diapause mode (dormancy under stress).** Organisms enter dormancy
(hibernation, seed dormancy, tardigrade cryptobiosis) under adverse
conditions, resuming when favorable. A "key hibernation" state: keys under
active/suspected threat can be cryptographically frozen — usable only via an
explicit multi-step wake ritual (passphrase + secondary-device confirmation +
cooldown timer) — rather than outright revoked, preserving them for later
un-hibernation if the threat assessment reverses. [speculative: whether users
would trust a "maybe-compromised, don't revoke yet" state over hard
revocation]

**Horizontal gene transfer for algorithm adoption (bacterial plasmid
exchange).** Bacteria share plasmids directly, propagating traits faster than
vertical inheritance. When two users interact (encrypt/sign to each other),
opportunistically exchange small signed "capability plasmids" — manifests of
which PQC algorithm combos each supports — accelerating discovery of what's
mutually usable without a central directory.

**Apoptosis for subkeys (programmed cell death).** Cells self-destruct via
internal signals when damaged, preventing tissue-wide harm. A subkey embeds
its own self-destruct policy in its signed packet (e.g. "if unused for 2
years AND flagged by 3 external signals, auto-expire") — the key carries its
own apoptosis trigger, distinct from relying purely on external revocation
infrastructure.

**Coral-bleaching early warning (stress-response threshold cascades).** Coral
expels symbiotic algae under thermal stress, a visible warning before death.
Model cryptographic "stress" (algorithm aging, keyserver unreachability,
repeated failed verifications) as an accumulating score per key, with the UI
visually "bleaching" a key's status color as stress accumulates — a gradient
early-warning distinct from binary healthy/revoked states.

**Pack-hunting consensus for multi-device signing (wolf pack coordinated
strategy).** Wolves coordinate differentiated roles (chasers, ambushers)
rather than duplicating effort. In multi-device threshold-signing setups,
assign devices differentiated roles (one proposes+drafts, others
independently verify+countersign) instead of symmetric M-of-N, reducing
redundant verification work while preserving the security property.

**Genetic-diversity bottleneck warning (population genetics: inbreeding
depression).** Low genetic diversity raises collective vulnerability to a
single pathogen. If a user's entire keyring converges on one PQC algorithm
family, warn of a "monoculture" risk — a single cryptanalytic break wipes the
whole keyring — and suggest deliberately diversifying algorithm families,
the way a breeding program maintains genetic diversity as insurance.

**Biofilm layered defense (multi-species protective matrix).** Biofilms
layer different microbial species into a matrix more resistant than any
single species alone. Composite algorithm packets already do this
structurally (ML-KEM+X25519); extend the *concept* app-wide as a "keyring
biofilm" mode that auto-layers defense-in-depth recommendations across all
crypto operations (storage encryption, passphrase KDF, transport) into one
coordinated, cohesively-scored matrix rather than independently-configured
settings.

---

## Lens 2: Physical / natural systems

**Phase-transition trust levels.** A phase transition flips a system's bulk
state discontinuously once a control parameter (temperature, pressure)
crosses a critical point, even though the underlying interactions changed
continuously. Model **trust-level upgrades** (e.g., "acquaintance" →
"verified" → "core contact") as phase transitions: the underlying evidence
(number of independent verification channels, freshness of signatures)
accumulates continuously, but the *displayed* trust state only flips at a
threshold, avoiding UI flicker on marginal evidence changes.

**Resonance-based multi-device sync.** Two pendulums on a shared support
synchronize through weak coupling (resonance) without any central clock.
Let two of a user's own devices (phone + VALKYRJA hardware key) "resonate" —
periodically exchange tiny liveness/state-hash beacons over a local
channel (BLE/NFC) so each can detect drift (one device has newer key state)
without a cloud sync service ever existing.

**Crystallography-based key fingerprint visualization.** Crystals grow
according to symmetry groups from a repeating unit cell. Replace the flat
QR-code-plus-hex-string fingerprint display with a **generative crystalline
lattice visualization** deterministically derived from the key fingerprint
bytes — visually distinct per key, so two different keys are recognizable at
a glance without reading hex, and identical keys always regenerate the exact
same lattice (a poor-man's perceptual hash).

**Fluid-dynamics laminar/turbulent import flow.** Laminar flow is smooth and
predictable below a critical Reynolds number; turbulence appears above it.
Frame the key-import wizard's complexity as a "flow regime": simple single-
key OpenPGP-wrapped imports stay in a "laminar" streamlined path (few
screens), but raw-seed imports, multi-identity imports, or conflicting-key
imports automatically route to a "turbulent" path with more checkpoints and
warnings — the UI complexity scales with actual import entropy, not a fixed
wizard.

**Optical interference for signature verification feedback.** Two waves in
phase reinforce; out of phase they cancel. Give signature verification a
literal interference-pattern animation: a valid signature shows two wave
patterns (expected hash, computed hash) constructively reinforcing into one
clean waveform; an invalid one visibly cancels into static — a physically
intuitive alternative to a green check / red X that also *shows the size of
the mismatch*, not just pass/fail.

**Thermodynamic entropy accounting for seed material.** Treat imported raw
seed material's entropy like a thermodynamic quantity that can only be
correctly estimated, never perfectly measured. Add an explicit **entropy
audit trail**: when raw seed is imported, the app records and displays its
best estimate of the entropy source's quality (device RNG, external QRNG via
VALKYRJA, user-supplied dice rolls) as permanent metadata attached to that
key, so a user auditing an old key later can see *why* they should or
shouldn't trust its origin.

**Self-organized criticality for backup nagging.** Sandpiles self-organize to
a critical slope where any new grain can trigger an avalanche of any size —
systems naturally evolve toward the edge of instability. Instead of periodic
backup reminders, monitor a "criticality" signal (days since backup, number
of new subkeys/identities since backup, device risk signals) and only nag
once accumulated risk crosses a naturally emergent threshold, avoiding
reminder fatigue while still catching the rare big "avalanche" (total device
loss with a stale backup).

**Refraction-based key-strength-at-a-glance icon.** Light bends differently
through media of different density. Encode each key's overall PQC posture
(classical-only / hybrid-composite / standalone-PQC) as a small icon showing
a beam bending at a different angle per category — a single glanceable
visual grammar usable in list views without reading algorithm names.

**Standing-wave passphrase strength meter.** A standing wave only forms when
wavelength and boundary conditions match constructively. Replace the linear
"weak → strong" passphrase bar with a resonance meter: the bar only "locks"
into a clean standing-wave pattern once the passphrase's entropy estimate
resonates with the security level the user says they need (e.g., "protecting
a Bitcoin cold-storage key" vs. "protecting a low-stakes throwaway
identity") — the *same* passphrase can show as sufficient or insufficient
depending on declared stakes.

**Superconductivity-style zero-resistance trusted paths.** Below a critical
temperature, resistance drops to exactly zero. Once a signature chain is
verified through enough independent, high-confidence paths, let the app
cache that chain as a "superconducting" trusted path that skips
re-verification overhead entirely (until any input changes), visually
distinct from ordinary "resistively" re-checked paths — an honest
performance/trust optimization with a physically-inspired mental model users
can actually reason about.

**Tidal-locking device pairing.** Two bodies tidal-lock when one's rotation
period matches its orbital period around the other, driven by gradual
gravitational damping. Frame long-term security-token pairing the same way:
early pairings need frequent re-confirmation; over a damping period of
successful pairings, the required re-confirmation frequency drops toward a
stable "locked" state — modeling trust decay/growth as damped oscillation
rather than a binary paired/unpaired flag.

---

## Lens 3: Mathematical / structural

**Functorial identity migration.** A functor maps between categories while
preserving structure (composition, identities). When a user migrates from a
v4 to a v6 primary key (or from classical-only to hybrid-composite), define
the migration as an explicit "functor" that provably carries over every
existing trust relationship (every third-party certification, every subkey
binding) into the new key's structure, with a machine-checkable proof
obligation that nothing was silently dropped — turning "did my
certifications survive migration?" from a hope into a checked property.

**Topological invariants for trust-graph health.** Topology studies
properties preserved under continuous deformation (connectedness, genus,
holes). Compute topological invariants of a user's personal web-of-trust
graph — is it connected? does it have "holes" (cliques of mutual trust with
no bridge between them)? — and surface these as a health metric distinct
from simple key-count, since a graph can have many keys and still be
topologically fragile (one bridge node away from splitting).

**Information-theoretic "surprise" alerts.** Shannon information content is
higher for less-expected events. Score every key-state change (new subkey,
revocation, algorithm change) by how *surprising* it is given the user's own
historical behavior pattern with that identity, and reserve the loudest
alerts for genuinely high-information-content events — routine renewal gets
a quiet log entry, an out-of-character algorithm downgrade gets a hard
interrupt.

**Graph-coloring for permission/capability separation.** Graph coloring
assigns labels so adjacent (conflicting) nodes never share a color. Apply
this to subkey capability assignment: automatically flag (color-conflict)
any proposed subkey configuration where two subkeys sharing a
security-token slot have "adjacent" capabilities that shouldn't overlap
(e.g., both being certify-capable), making a whole class of dangerous
configurations visually detectable as a coloring failure rather than a
buried validation error.

**Category-theoretic composable trust policies.** Instead of one monolithic
trust-policy object, define small composable trust "morphisms" (a policy is
a function from evidence to trust-level) that compose associatively — so a
user (or an organization) can build a bespoke trust policy by chaining
primitive policies (e.g., "require 2 independent certifiers" ∘ "require a
security-token-bound key" ∘ "require freshness < 90 days") the same way
Unix pipes compose, instead of a fixed set of checkboxes.

**Group-theoretic key-share symmetry for social recovery.** In Shamir
secret sharing, any k-of-n shares suffice — but real deployments often want
*asymmetric* trust (spouse's share should outweigh acquaintance's share).
Generalize using weighted/hierarchical secret sharing (a genuine
group-theoretic generalization of Shamir), and expose it in the UI as
literally assigning "weight" sliders to each recovery contact rather than
forcing the user into unweighted k-of-n.

**Metric-space "distance" between identities.** Define a formal distance
function between two OpenPGP identities based on shared certifiers, shared
algorithm choices, and interaction history, satisfying real metric axioms
(triangle inequality etc.), and use it to power a "people you might also
trust" recommender that's mathematically principled rather than an ad hoc
heuristic — and, critically, is *explainable* because the distance function
is inspectable.

**Homomorphic-property key ceremonies.** Some cryptographic constructions
allow computing on encrypted data without decrypting. Explore a **multi-
party key generation ceremony** where several devices (e.g., phone +
VALKYRJA hardware key + an offline backup device) jointly contribute entropy
to a single ML-KEM/ML-DSA keypair such that no single device ever holds the
full private material, using an MPC-style ceremony UI modeled after
threshold signature setup flows. [speculative: rests on a practical,
audited MPC key-generation protocol existing for the specific PQC schemes in
use, which is an active research area, not settled]

**Persistent-homology "shape" of a key's history.** Persistent homology
tracks which topological features (holes, connected components) survive
across a filtration (a sequence of nested spaces) — features that persist
longest are considered "real," not noise. Apply the same idea to a key's
audit log: features of a key's history that persist across many independent
verification events (keyserver checks, in-person verifications, security-
token re-pairings) are highlighted as the "real" trust signal, while
one-off events that don't persist are visually deprioritized as likely
noise.

**Error-correcting-code redundant social backup.** Instead of plain Shamir
splitting (any k-of-n), use an erasure code (like Reed-Solomon) so recovery
shares can be *regenerated* from any sufficient subset and new shares
minted for new trusted contacts without ever reconstructing the original
secret in the process — letting a user add or replace a recovery contact
over time without a full re-split ceremony.

### Second independent pass (mathematical lens, run in parallel)

**Trust betweenness heatmap.** Graph betweenness centrality. Visualize the
web-of-trust graph with keys sized/colored by betweenness; flags "bridge"
identities whose compromise fractures trust into disconnected components.

**Minimum trust-cut warning.** Max-flow/min-cut. Compute the minimum cut
separating you from a contact's trust path; if the min-cut is 1, surface
"this contact's trust to you depends entirely on Key X."

**Trust cycle rank.** Topology (first Betti number / cycle rank). Score
contacts by how many independent mutual-certification loops connect you —
redundant verification paths mean resilience, made visible as a number.

**Compositional key-derivation pipeline.** Category theory (functors,
morphism composition). Chain key-transform operations (derive
encryption-only view ∘ derive time-boxed view) as literal composable,
type-checked morphisms in a pipe-builder UI instead of ad hoc menus.

**Entropy budget meter.** Shannon entropy / information theory. Real entropy
estimation (not a naive strength bar) for passphrase/seed material, tracking
how much distinguishability each derived subkey "spends." [speculative:
entropy estimators are imperfect proxies for real-world guessability]

**Manifold trust map.** Geometry / dimensionality reduction (UMAP-style
embedding). Project the trust graph onto 2D/3D so keys with similar trust
neighborhoods cluster spatially — a literal map of your trust communities.
[speculative: embedding proximity is not proven semantic clustering]

**Group-action rotation policies.** Group theory (group actions/orbits).
Model key-rotation schedules as composable elements of a rotation group
(cyclic policies ∘ compromise-triggered policies) instead of ad hoc cron
rules — composition is guaranteed predictable by construction.

**Homomorphic capability delegation.** Algebra (structure-preserving
homomorphisms). Formally verify that a delegated/restricted subkey's
capabilities are a true homomorphic image of the parent's — catches subtle
capability-leak bugs by construction, the same bug class as this session's
KEM-master-key hang, but caught by a verifier instead of a user report.

**Graph-coloring identity-segregation checker.** Graph coloring / chromatic
number. User declares "identity X must never touch identity Y"; the app runs
coloring on the conflict graph and flags accidental cross-certification —
directly useful for Onna-Bugeisha-style pseudonymous flows.

**Deniability score via mutual information.** Information theory. A rough
MI-based estimate of how much an observer could infer about which identity
produced a signature, surfaced especially for standalone (non-standard) PQC
keys, which have a distinctive wire signature. [speculative: real
traffic-analysis resistance isn't fully captured by a simple MI estimate]

**Functor-based format adapters.** Category theory (functors between format
categories). Architect import/export as functors so adding one new format
composes automatically with all existing ones instead of hand-writing N²
converters — an internal architecture idea that unlocks fast interop with,
e.g., Onna-Bugeisha wallet formats.

**Curvature-weighted certification strength.** A Ricci-curvature-like graph
measure. Weight trust not just by certifier count but by how structurally
independent the certifiers are (a tight clique means low true confidence,
distant/non-overlapping neighborhoods mean high) — improves on OpenPGP's
naive certification-count model. [speculative: novel, unproven as a genuine
independence measure]

**Key-graph genus ("recovery loop count").** Topology (genus). One number:
how many independent recovery loops exist across your devices/tokens/
backups. Genus 0 means a single point of failure — an actionable backup
nudge.

**Homotopy-equivalent migration paths.** Topology (homotopy equivalence).
Model classical→composite→standalone PQC migration as a continuous
deformation; compute and show whether a migration step is
homotopy-equivalent (all contacts retain verification) or breaks continuity
(some contacts lose it) — turns "will my contacts still trust me" from a
guess into a computed guarantee.

---

## Lens 4: Social / economic

**Reputation-market-style certifier weighting.** In prediction markets,
a participant's influence on the aggregate price is implicitly weighted by
their track record of being right. Weight each certifier's signature in a
user's trust computation not just by "did they sign" but by a locally-
computed track record: certifiers whose past certifications correlated with
keys that later proved reliable (long-lived, never revoked-for-compromise)
get more implicit weight in the app's own trust scoring — entirely local,
no central reputation server. [speculative: assumes "long-lived, never
revoked" is a good proxy for a certifier's judgment quality, which is a
design bet, not a proven metric]

**Gift-economy key vouching.** In gift economies, status comes from giving,
and there's a social expectation (not a contract) of eventual reciprocity.
Let certifying someone else's key create a lightweight, revocable "vouch"
distinct from a formal OpenPGP signature — a low-ceremony social layer for
"I'm willing to informally vouch for this identity to my other contacts,"
visible in-app as a softer trust signal than a full certification, lowering
the activation energy for building web-of-trust density.

**Guild-style organizational key custody.** Medieval guilds distributed
authority and apprenticeship structurally, not just hierarchically. Offer a
"guild" key-custody mode for teams: a master signing key requires N-of-M
guild-member co-signatures for certain operations (revocation, adding a new
guild member), modeled as a lightweight local governance structure rather
than a hosted enterprise-KMS product — useful for small orgs, families, or
activist groups who need shared custody without a SaaS vendor.

**Insurance-style key-risk pooling (informational, not financial).**
Insurance pools uncorrelated risks. Let privacy-respecting, opt-in,
*local-only* aggregation of "which algorithm choices have needed emergency
rotation" across a user's own trust circle (via explicit peer-to-peer
sharing, never a central server) surface as a soft warning signal — "3 of
your 20 contacts using algorithm X rotated for suspected compromise in the
last year" — giving informational herd-immunity without any actual data
pooling infrastructure.

**Auction-style priority for constrained hardware-token operations.**
Security tokens have limited concurrent operation slots/battery. If a user
has multiple pending operations queued against one token, let the UI expose
an explicit "priority bid" mechanic (not real money — just user-assigned
priority weight) so time-sensitive operations (an in-progress video call
needing a signature now) can jump the queue ahead of a background bulk
re-signing job, borrowing auction mechanics' allocation-under-scarcity
structure without any actual currency.

**Contract-law style "key covenants."** Contracts formalize obligations
between parties with defined remedies for breach. Let two users establish
an explicit, cryptographically-signed "covenant" (e.g., "we will both
rotate keys within 30 days of either being suspected compromised, and each
will notify the other") that the app can locally track and remind about —
formalizing a social security agreement that currently only exists as
informal expectation.

**Cooperative/credit-union custody of shared organizational keys.** Credit
unions are member-owned, not shareholder-owned — governance mirrors usage.
For a guild/team key (see above), let voting weight on custody policy
changes be proportional to actual usage/participation (who's actually
signing, verifying, showing up) rather than a fixed initial allocation,
so custody governance drifts naturally toward the people actually doing the
work.

**Escrow-style time-locked emergency access.** Real-estate escrow releases
funds only when conditions are independently verified. Offer a **dead-man's
-switch key escrow**: designate a trusted contact who can only access a
specified subset of key material after BOTH a time condition (no check-in
for N days) AND an explicit secondary confirmation from a third party
resolve — reducing the classic single-point failure of naive dead-man's
switches.

**Marketplace-style algorithm "menu" with transparent tradeoffs.**
Borrow farmers-market price-tag transparency: every PQC algorithm choice in
the key-creation UI shows a small, honest "tradeoff tag" (key size, sig
size, standardization status, interoperability) right next to the
selector, the way a market stall shows origin/price/organic-status,
instead of burying tradeoffs in a help doc — informed choice at the point
of decision.

### Second independent pass (social/economic lens, run in parallel)

**Sybil-resistant web of trust via stake-weighted attestation.**
Proof-of-stake weights validator influence by locked economic stake, making
Sybil attacks costly. Certifications carry more weight if the certifying key
has "skin in the game" — long tenure, prior certifications that held up,
cross-verification by others — a computed "trust capital" score rather than
flat signature-counting, resistant to cheap-to-mint sockpuppet
certifications.

**Escrow-style key recovery (multisig escrow markets).** Real-estate escrow
splits control three ways (buyer, seller, neutral agent) so no single party
can unilaterally act. A built-in "social recovery escrow" mode splits
recovery material across N trusted contacts plus one neutral party, requiring
M-of-N cooperation to reconstruct — recovery as a market-style trust
instrument, not just Shamir math.

**Reputation bonding curves for algorithm adoption.** Bonding curves price a
token based on cumulative supply, creating early-adopter incentive without
central issuance. Keys that adopt composite/standalone PQC earliest get a
visibly higher "migration reputation" badge that decays in marginal value as
adoption becomes universal — social pressure via a decaying-scarcity signal,
not a leaderboard.

**Guild certification tiers (medieval apprentice→journeyman→master).**
Guilds gated skill progression through witnessed, irreversible rites tied to
demonstrated competence. A freshly generated key is an "apprentice" key
(encryption-only trust), gains "journeyman" status after N successful
verified signs/decrypts over time, and "master" (full certify authority)
only after a deliberate, friction-full ceremony — trust earned through use,
encoded into UI state.

**Dutch-auction revocation urgency.** Dutch auctions start high and decay
until someone accepts. For ambiguous "possibly compromised" keys, run a
decaying-severity countdown: initially high-alert (block all ops), decaying
toward normal severity if no confirming evidence arrives within a window —
replaces binary revoked/not-revoked with a resolving uncertainty window.
[speculative: whether a decaying-alert UX is legible/trustworthy to end
users]

**Gift-economy key-signing parties (potlatch).** Status in a potlatch comes
from giving away resources, not hoarding. A "digital signing party" mode:
users gather (in person or via a session code) and mutually certify each
other's keys in a single batch ceremony, framed and gamified as a
gift-exchange event with a shared session receipt — relaunches the
historically clunky WoT-building ritual as something social and legible
again for a PQC-migration era.

**Insurance-pool model for compromise response (mutual aid societies).**
Mutual insurance spreads individual risk across a voluntary collective. A
community "compromise response pool": opted-in users get faster propagation
of revocation-relevant intelligence ("this keyserver is serving stale data,"
"this algorithm just got broken") from a shared threat feed maintained by
the pool's own participants.

**Market-clearing algorithm negotiation.** Auctions clear by matching bid/ask
without either party needing full information about the other. When two
users' clients support different composite/standalone PQC combos,
auto-negotiate the cheapest mutually-acceptable algorithm set the way an
exchange matches orders — invisible protocol negotiation instead of manual
algorithm picking.

**Governance quorum for org-level trust-policy changes (constitutional
supermajority).** Constitutions require supermajorities for amendments. For
organizational deployments, changes to org-wide trust policy require
multi-admin quorum sign-off recorded as a signed policy-change certificate,
not a single admin toggle.

**Franchise model for institutional sub-identities.** Franchises operate
semi-independently under a shared brand with contractual boundaries. An
organization issues "franchise" sub-keys to departments/employees that
inherit certification from a master org key but carry their own scoped
algorithm/usage policy — closer to a corporate hierarchy a business user
already understands than a flat WoT.

**Prediction-market-style confidence aggregation for contested
fingerprints.** Prediction markets aggregate dispersed private information
into a single price better than any individual forecaster. When multiple
independent verification channels (in-person, keyserver, WKD, out-of-band)
disagree slightly on a fingerprint's status, aggregate into a single
displayed confidence percentage rather than conflicting binary badges.

**Vesting-cliff cooldown for high-stakes key operations.** Startup equity
vesting delays full ownership to align incentives over time. A newly
generated or imported *master* key can encrypt/decrypt immediately but can't
exercise certify authority until a time-delay or secondary-device
confirmation "vests" — reduces blast radius of a freshly-compromised-at-birth
key.

**Public-goods dashboard for keyserver ecosystem health.** Crowdfunding
platforms sustain trust in the commons with real-time funding-health
dashboards. Surface a transparent "health of the PQC keyserver ecosystem"
panel in-app (how many keyservers support `draft-openpgp-pqc`, uptime,
adoption %) — infrastructure as a visible public good, not an invisible
backend.

**Mutual-credit model for cross-org trust bridging (LETS — Local Exchange
Trading Systems).** Mutual credit lets unconnected parties trade via a
shared IOU ledger without a common trusted third party. For federated orgs
without a shared CA: a lightweight mutual-credit-style cross-certification
ledger where each org "extends credit" (vouches) for specific counterpart
keys, auditable and revocable, without a global PKI authority. [speculative:
governance/liability model for who's accountable when a vouch turns out
wrong]

**Escheatment for abandoned keys (unclaimed-property law).** Unclaimed
financial property escheats to the state after a dormancy period, following
strict legal process. Define an app-level "dormant key" archival tier for
long-inactive, non-revoked keys — a nudge to the owner if still reachable, or
a clear "last seen" provenance trail for anyone relying on it — instead of
silently forgetting them.

---

## Lens 5: Artistic / craft / mythic / ritual / linguistic

**Musical-counterpoint multi-voice signature composition.** Counterpoint
combines independent melodic lines that remain harmonious together. Give
composite signatures (ML-DSA + Ed25519) a literal audible or visual
"counterpoint" representation — two independent voices (classical, PQC)
that must resolve consonantly for the composite to verify — making the
*idea* of hybrid signing intuitively graspable to non-cryptographers as
"two voices agreeing," not "two algorithms concatenated."

**Choreography-based multi-step ceremony guidance.** Dance notation
(Labanotation) encodes complex multi-body movement as precise, learnable
sequences. Apply the same rigor to multi-device key ceremonies (e.g.,
setting up a security token alongside a phone-held backup key): a literal
step-by-step "choreography" view showing which device does what and when,
reducing the real-world failure mode of users losing track of ceremony
state halfway through.

**Weaving/textile structural metaphor for composite algorithms.** A woven
textile's strength comes from warp and weft threads interlocking, not just
being adjacent. Visualize composite (classical+PQC) keys as an actual woven
pattern in the UI — literally interlaced threads — so the *security
argument* ("breaking this requires breaking both threads, not just one") is
shown structurally, not just stated in a tooltip.

**Architectural load-bearing metaphor for primary-vs-subkey roles.**
Buildings distinguish load-bearing walls from partitions. Rethink the key
hierarchy visualization as a literal architectural cross-section: the
primary/certify key as foundation and load-bearing structure, subkeys as
rooms/partitions that can be added, removed, or reconfigured without
touching the foundation — an immediately intuitive mental model for why
losing a subkey isn't catastrophic but losing the primary is.

**Ritual "rite of passage" framing for the molt/regeneration ceremony**
(see biological lens above). Rites of passage have a three-part structure:
separation, liminal transition, reincorporation. Give the "molt" key-
regeneration flow this exact three-act structure in the UI copy and flow —
an explicit "leaving your old identity behind" screen, a liminal "in
transition, both keys temporarily valid" period with visible countdown,
and a "welcome to your new identity" reincorporation screen with the molt
certificate — turning a scary destructive action into a legible, even
meaningful, process.

**Oral-tradition mnemonic seed encoding.** Oral traditions preserve huge
amounts of information via structured mnemonic devices (meter, rhyme,
formula) long before writing. For raw-seed key backup, offer (alongside
the existing hex/file options) a **structured mnemonic phrase** encoding
(BIP39-style, but explicitly extended/reworked for PQC's larger seed
material) with built-in checksum words, so backup can be memorized or
verbally relayed the way oral formulas survived transmission errors for
millennia.

**Grammar/linguistic parse-tree visualization of composite certificates.**
A sentence's meaning is legible from its parse tree (subject, verb, object,
modifiers). Render a composite OpenPGP packet's structure (primary key,
subkeys, composite signature components, notation packets) as an actual
collapsible parse tree in an "advanced view," so power users can read a
key's real structure the way a linguist reads a sentence, instead of a flat
hex dump.

**Alchemical transmutation framing for algorithm migration.** Alchemy's
core narrative is patient, careful transmutation of one substance into a
purer form through defined stages, not instant transformation. Frame the
classical→hybrid→standalone-PQC migration path explicitly as stages (a
"transmutation" progress view: Leaden/classical-only → Silver/hybrid →
Gold/standalone-verified) — gamifying security posture improvement with a
narrative that's culturally resonant with the alchemy-heavy branding
already used elsewhere in the operator's portfolio (Onyx VALKYRJA, Onna-
Bugeisha).

**Constellation/cosmology mapping of a user's whole trust graph.** Star
charts turn scattered points into memorable named shapes. Auto-generate a
personal "constellation" view of a user's full trust graph — contacts as
stars, certifications as connecting lines, clustered into named
"constellations" by community-detection — turning an abstract graph into
something a user can navigate by spatial/narrative memory rather than a
scrolling list.

**Call-and-response verification UX for in-person key exchange.**
Call-and-response is a robust communication pattern precisely because
errors are caught immediately by the mismatch between call and response.
Redesign in-person fingerprint verification as an explicit call-and-response
script the app coaches both parties through aloud ("you say the first four
words, they confirm, they say the next four") rather than two people
silently squinting at hex on two screens — a proven low-error-rate human
protocol borrowed directly.

---

## Lens 6: Engineering from other industries

**Aerospace pre-flight checklist for key ceremonies.** Aviation checklists
exist because complex irreversible procedures under stress benefit from
externalized, non-memory-dependent verification. Give every irreversible
key operation (revocation, molt, primary-key generation) a literal
checklist UI modeled on aviation pre-flight checklists — each item must be
explicitly acknowledged in order, no skipping, with a final "cleared for
takeoff" confirmation — instead of a single "are you sure?" dialog.

**Surgical time-out / sponge-count for multi-step operations.** Surgery
uses a mandatory pre-incision "time-out" (whole team pauses, confirms
patient/procedure/site) and a post-op instrument count to catch errors
before they become irreversible. Apply a "time-out" pattern before any
destructive multi-key-touching batch operation (bulk revocation, mass
re-signing) — an explicit pause-and-confirm screen listing exactly what's
about to be touched, plus a post-operation "count" screen confirming what
was actually changed matches what was intended.

**Logistics hub-and-spoke routing for multi-device key sync.** Shipping
networks route through hubs rather than point-to-point when N is large.
For users with many devices/tokens, route key-state sync through a
user-designated "hub" device (e.g., the VALKYRJA hardware unit) rather than
every device needing pairwise sync logic — dramatically simplifying the
N² pairwise-sync problem into N spoke connections.

**Brewing-style batch/lot tracking for key material provenance.**
Breweries track every batch's ingredients, process parameters, and lot
number for traceability and recall. Give every generated key a permanent,
inspectable "batch record": which app version, which RNG source, which
algorithm library version, generated it — so if a future audit discovers a
flaw in a specific library version or RNG, affected keys are instantly
identifiable by batch, the way a contaminated ingredient triggers a
targeted recall instead of guessing.

**Semiconductor-fab-style "clean room" import mode.** Fabs use graduated
cleanroom classes (fewer particles = higher class) with strict ingress
protocols. Offer a "clean room" import mode for maximum-sensitivity keys:
import only proceeds if the device is in a verified state (no other apps
recently installed, airplane mode on, screen-recording/accessibility
services off) — a graduated, inspectable "cleanliness class" the app checks
and displays before allowing import, rather than a binary permission
prompt.

**Theatre-rigging redundant load-path safety.** Rigging above a live
audience uses redundant independent load paths (a safety cable in addition
to the primary line) specifically so a single failure can't drop the load.
Require (or strongly recommend) that any key protecting high-stakes
material always have a structurally independent backup path (different
algorithm family, different storage medium) — and visually flag keys that
are "single load path" the way a rigger would flag an unsafed line.

**Air-traffic-control conflict-detection for concurrent key operations.**
ATC systems proactively project trajectories forward to flag conflicts
before they happen, not just when planes are already close. Proactively
simulate the near-future consequences of a pending key operation (e.g.,
"revoking this subkey will break signature verification for these 3
recent messages you sent") and surface the *projected* conflict before
the user commits, rather than only failing after the fact.

**Pharmaceutical blister-pack adherence patterns for scheduled key
hygiene.** Blister packs use physical/visual structure (day-of-week
labeling) to make a hard-to-track behavior (daily adherence) legible at a
glance. Apply the same "make the missed step visually obvious" principle
to periodic key-hygiene tasks (backup verification, keyserver refresh,
expiry renewal) — a persistent, glanceable calendar-grid widget showing
which weeks were "taken" (completed) vs. missed, rather than a single nag
notification easily dismissed and forgotten.

**Structural-engineering load-testing before deployment.** Bridges are
load-tested (sometimes to destruction on prototypes) before carrying real
traffic. Before a new primary key "goes live" as a user's daily driver,
offer an explicit **dry-run load test**: simulate a batch of realistic
operations (sign, encrypt, decrypt, verify against test messages) against
the new key configuration end-to-end, surfacing any failure (e.g., the
KEM-only-master-key hang class of bug this session already found and
fixed) *before* the user starts depending on it for real messages.

### Second independent pass (cross-industry engineering lens, run in parallel)

**Pre-flight key-ceremony checklist.** Aviation checklists force explicit,
sequential verification of otherwise-invisible state before an irreversible
action, each item an active acknowledgment, not a default-yes. Before
generating a new primary key or revoking one, walk the user through a
mandatory sequential checklist (backup exists? passphrase tested? algorithm
choice reviewed? revocation certificate exported?) where each step must be
individually confirmed, not batch-approved.

**Redundant diverse actuators → algorithm-diversity enforcement.** Aerospace
flight-critical systems use actuators built on different physical principles
(hydraulic + electric + pneumatic) so one failure mode can't take out all of
them. A "critical identity" key can be required to carry at least two
structurally different signature algorithms (e.g. lattice-based ML-DSA and
hash-based SLH-DSA) as a hard app-enforced policy, so a single cryptanalytic
break of one mathematical family doesn't zero out the identity.

**Blood-bank chain-of-custody for key export.** Blood-bank custody requires
an unbroken, signed log of every handoff, each custodian cryptographically
attesting receipt. Every export of secret key material generates a signed
custody record — who/what received it, when, over what channel — stored
locally as a queryable audit trail.

**Semiconductor-fab cleanroom gating for key generation.** Fab cleanrooms
gate entry by contamination class, stricter protocols for more sensitive
steps. Gate key-generation "cleanliness" similarly: generating a primary key
while the device shows signs of contamination (screen recording active,
unknown accessibility service running, ADB debugging enabled) triggers a
warning or hard block, scaled to the operation's sensitivity.

**Theatre-rigging redundant load paths.** Stage rigging never hangs a load
from a single line — every flown piece has a secondary safety cable rated to
catch it if the primary fails. Every primary key's protection gets both a
"primary line" (passphrase) and a "safety cable" (an independently-stored
recovery mechanism) that the app actively nags the user to set up as routine,
not an afterthought.

**Nuclear-reactor SCRAM (fail-safe default state).** A reactor's default
failure mode is shutdown, not "last known state" — ambiguity always resolves
toward safety. Any operation where the app can't fully verify a precondition
(can't confirm keyserver reachability, can't confirm token firmware version)
defaults to refusing/warning rather than proceeding optimistically — an
explicit "fail-closed by default" mode, toggleable for advanced users who
want fail-open convenience. [speculative: whether fail-closed-by-default
hurts adoption more than it helps security in practice]

**Logistics manifest reconciliation.** Freight logistics reconciles a
shipping manifest against actual received goods at every handoff, flagging
discrepancies immediately. When importing a key, generate a "manifest" of
what's expected (algorithm mix, identity count, subkey capabilities) versus
what's actually parsed, and surface any discrepancy as an explicit diff
before import completes.

**Brewing's batch/lot provenance tracking.** Brewers trace every batch's lot
number back through every ingredient's own lot, so contamination can be
traced without recalling everything. Every generated key carries a
"provenance lot" — app version, RNG source, algorithm library version, and
device attestation state at generation time — so a later-discovered
dependency vulnerability lets users query "which of my keys came from a
contaminated batch" instead of treating the whole keyring as suspect.

**Mining/tunneling ground-truth instrumentation.** Tunnel boring operations
continuously instrument stress/strain around the bore, not just at the face,
because failure can develop invisibly behind where you're actively working.
Continuously (locally, no network) monitor "environmental stress" around
stored key material — repeated failed unlock attempts, unusual access
patterns, device-state changes — and surface a background "structural
integrity" indicator for the whole keyring.

**Surgical time-out protocol (verify identity before the cut).** Surgery's
mandatory pre-incision "time-out" pauses the team to verbally reconfirm
patient identity and procedure, specifically because it's the step people
are most tempted to skip when confident. Before any destructive key
operation (delete, revoke, overwrite via import), force a "time-out" screen
requiring the user to read back a specific identifying detail (fingerprint
suffix, key name) rather than tap a generic "are you sure?" — breaks the
autopilot-confirm reflex.

**Civil engineering's load rating and inspection interval.** Bridges get a
formal load rating and mandated re-inspection interval scaled to
age/materials/traffic, not "inspect when it looks bad." Assign each key an
app-computed "load rating" (contacts, traffic volume, criticality of
attached identities) and use it to set a suggested re-verification/rotation
interval instead of a flat one-size-fits-all expiration policy.

**Aerospace black box for crypto operations.** Flight recorders capture the
last N minutes of every relevant parameter in a crash-survivable,
append-only store, specifically so post-incident analysis doesn't rely on
memory. Maintain a local, tamper-evident, append-only log of the last N
cryptographic operations in a separate hardened store, so a suspected
compromised device has ground truth instead of reconstructed app state.

**Anesthesia-machine interlocks (can't proceed until precondition met).**
Anesthesia machines physically/electronically interlock so gas flow cannot
start until oxygen supply is confirmed present — enforced by the machine, not
operator discipline. Make certain dangerous configurations *mechanically
impossible* rather than merely warned against — e.g. the app should be
unable to construct a primary key with only KEM-capable subkeys and no
signing capability at the data-model level, generalizing the KEM-only-
master-key fix already shipped this session app-wide.

**Semiconductor wafer yield binning.** Fabs sort finished chips into
speed/quality bins based on actual measured performance, not just pass/fail.
After key generation, actually measure the produced key against quality
heuristics (entropy estimate, parameter strength, cross-check against
known-weak-key databases) and bin/label the result instead of treating all
successful generations as equivalent.

**Air-traffic-control handoff protocol.** ATC handoff requires the receiving
controller to explicitly accept and read back key parameters before
responsibility transfers — it never transfers silently. Model key-custody
transfer (moving primary key material to a new device) as an explicit
two-sided handoff: the new device must actively "accept" and read back a
verification value before the old device's copy is offered for destruction.

---

## Lens 7: Cross-pollination with the operator's own portfolio

**VALKYRJA hardware as the QRNG entropy root for OpenKeychain PQC.**
VALKYRJA's roadmap includes a glass photonic QRNG. If/when that hardware
exists, OpenKeychain PQC could consume it directly as a certified entropy
source for key generation over the same HNCP-style compartmentation
already designed for VALKYRJA, giving this Android app access to genuinely
better randomness than any phone's onboard TRNG — with the "entropy audit
trail" concept from Lens 2 recording exactly that provenance.

**Onna-Bugeisha ↔ OpenKeychain PQC shared ML-DSA-65 identity.** Onna-
Bugeisha already uses ML-DSA-65 PQ signatures for its wallet identity.
A user could derive (or cross-certify) their Onna-Bugeisha wallet identity
and their OpenKeychain PQC OpenPGP identity from a shared root-of-trust
ceremony, so "prove this Bitcoin address and this email identity belong to
the same post-quantum-secure person" becomes a single verifiable
certificate instead of two disconnected trust silos.

**QWAMOS compartmentation model applied to OpenKeychain's own key
storage.** QWAMOS's Qubes-style compartmentation (separate VMs per trust
domain) is a structural pattern independent of VALKYRJA's specific
hardware. Even on stock Android, borrow the *policy* — different key
"compartments" (personal, work, high-stakes) with explicit, auditable
cross-compartment access rules — rather than one flat keyring, mirroring
QWAMOS's philosophy at the app level without needing the hypervisor.

**Cryptanalytic Research's algebraic-attack findings as a live advisory
feed.** The cryptanalysis research track studies algebraic structure
attacks against ECC/PQC primitives. A (strictly local, no phone-home)
mechanism for the operator to manually push "algorithm X shows structural
weakness in scenario Y, consider avoiding it for new high-stakes keys"
advisories into OpenKeychain PQC's own algorithm-selection UI, closing the
loop between the research and the deployed tool it should inform — the
research findings would directly gate which algorithms the UI recommends,
the way `β-Oracle`-class findings already reinforce the PQC-only
commitment for VALKYRJA's threat model.

**Cytherea-style soft-guardrail security prompts instead of hard gates.**
Cytherea's design philosophy is soft guardrails, not hard governance gates
— informed autonomy over paternalistic blocking. Apply the same philosophy
explicitly to OpenKeychain PQC's own UX: instead of hard-blocking
"dangerous" configurations (like the original KEM-only-master-key bug this
session fixed by *excluding* the option), some *lower*-stakes edge cases
could instead get a strong, well-explained warning the user can
consciously override — consistent cross-project design language between
two of the operator's own products.

**Mindforge session-log JSON schema pattern reused for key-audit logs.**
Mindforge's Remote Viewing tool already has a proven single-file,
portable session-log JSON schema consumed by Cytherea's Q-Viewer. Reuse
that *pattern* (not the schema itself) for OpenKeychain PQC's key-audit
trail: a portable, single-file, human-and-machine-readable audit log per
identity that a user could export and inspect the same way Mindforge
session logs are inspected — cross-project consistency in "how do we make
an audit trail legible" rather than inventing a bespoke format.

**HNCP-style kill-switch concept applied to passphrase caching.**
VALKYRJA's design includes hardware kill switches — an immediate, trusted,
out-of-band way to cut power/connectivity. A software-analogue "kill
switch" gesture in OpenKeychain PQC (a specific, hard-to-accidentally-
trigger action) that instantly and unconditionally flushes the passphrase
cache and re-locks every key, for the moment a user needs to hand their
unlocked phone to someone else or the device is being seized.

### Second independent pass (cross-portfolio lens, run in parallel)

**Shared PQ identity root (Onna-Bugeisha).** Onna-Bugeisha already uses
ML-DSA-65 for wallet signatures. OpenKeychain PQC could export/import a
key's ML-DSA-65 material as the *same* identity root the wallet uses, so a
user's OpenPGP identity and Bitcoin-wallet identity are cryptographically the
same key, not two unrelated keypairs to separately trust — concretely, an
"export as Onna-Bugeisha identity seed" action on any ML-DSA-65-capable key.
[speculative: rests on Onna-Bugeisha's key-import format accepting external
OpenPGP-wrapped ML-DSA material]

**QRNG-sourced key generation (VALKYRJA).** VALKYRJA's glass photonic QRNG
roadmap is a hardware entropy source. A pluggable entropy-source interface
means key generation on VALKYRJA hardware (or any device exposing a QRNG via
HNCP) pulls raw entropy from the photonic QRNG instead of Android's software
RNG, surfacing which entropy source was actually used as part of the key's
provenance metadata. [speculative: HNCP entropy-exposure interface doesn't
exist yet]

**HNCP kill-switch propagation to key revocation.** VALKYRJA's kill switches
are a hardware-level "everything stops" mechanism. Wire a kill-switch event
(via HNCP) to trigger OpenKeychain PQC's local key-hibernation/revocation
flow automatically — if the hardware kill switch fires, keys on that device
auto-hibernate rather than requiring a separate manual step.

**Cryptanalytic Research feedback loop.** The Cryptanalytic Research
workstream does algebraic attacks against PQC primitives. A private, opt-in
channel lets OpenKeychain PQC's algorithm-selection UI be directly informed
by that research — if an internal cryptanalysis result weakens confidence in
a parameter set, the picker can de-prioritize or flag it before any public
NIST/IETF advisory exists, with a clear internal-advisory vs. public-advisory
UI distinction so users understand the warning's provenance.

**QWAMOS compartment-bound keys.** QWAMOS's Qubes-style compartmentation
means different security domains run in different VMs. OpenKeychain PQC
could support "compartment-scoped" keys cryptographically bound (via a
compartment-ID field in a signed notation packet) to a specific QWAMOS qube,
so a key generated in a "work" compartment refuses to sign from a "personal"
compartment context, enforced by an HNCP-aware permission check rather than
UI convention alone.

**Cytherea Q-Viewer session signing.** Mindforge's Remote Viewing tool
session logs feed Cytherea's Q-Viewer, with "coordinate hash" the only field
crossing that boundary today. Users could sign that coordinate hash with
their PQ identity key before it crosses into Cytherea, giving the RV session
log a verifiable, non-repudiable origin — cryptographic chain-of-custody for
an internal research pipeline that might later need integrity proof.

**Soft-guardrail-compatible key policies (Cytherea).** Cytherea's six-layer
architecture explicitly commits to soft guardrails over hard gates.
OpenKeychain PQC's key policies are currently hard (a KEM-only key literally
cannot be selected as primary). An alternate "soft" policy mode, used only
when a key is explicitly flagged for Cytherea-adjacent use, would warn
strongly but not hard-block unconventional configurations. [speculative:
direct tension with "no silently weakening security invariants" — flagged
explicitly for operator judgment, not a settled recommendation]

**Mindforge single-file tool signing/verification widget.** Mindforge's
whole architecture is "single-file purity." A minimal, embeddable
single-HTML-file verifier (a stripped-down WASM build of just the
ML-DSA/SLH-DSA verify path) would let Mindforge's nine tools each embed a way
to verify a specific tool file's signature offline, in-browser, with zero
dependency on the OpenKeychain app being installed.

**VALKYRJA HSM-backed key storage.** VALKYRJA's threat model includes an
HSM. An HSM backend option (via HNCP) means that on VALKYRJA hardware, the
highest-value private key material never touches the Android application
layer at all — signing operations relay to the HSM and only the result
returns, making OpenKeychain PQC a *client* to VALKYRJA's HSM rather than the
key custodian on that hardware. [speculative: rests on VALKYRJA's HSM
exposing a signing API compatible with OpenPGP's operation model]

**Atomic-swap counterparty identity via OpenPGP (Onna-Bugeisha Ryôgae).**
Onna-Bugeisha's BTC-XMR atomic swaps need counterparty authentication
distinct from the swap protocol's own cryptography. OpenKeychain PQC keys
could serve as the out-of-band identity layer for swap counterparties —
verifying "this Monero address belongs to the person I already have a
PQ-signed OpenPGP relationship with" before initiating a swap, layering
social trust on top of the protocol-level guarantees the
atomic-swap-formalist agent already verifies.

**Whirlpool CoinJoin round-announcement signing.** Onna-Bugeisha's Whirlpool
CoinJoin coordinator broadcasts round announcements. Signing them with a
coordinator's OpenKeychain PQC key, independently verifiable by any client,
gives round integrity a second, well-audited verification path
(OpenPGP/RFC-grounded) distinct from the Blind-Schnorr-over-Ristretto
protocol-level signature — defense-in-depth against a bug in the primary
scheme. [speculative: adds complexity/overhead to an already
latency-sensitive coordination round — a real design tension, not just a
crypto question]

**Cross-project "trust passport" export.** A single OpenKeychain PQC
identity could generate scoped, purpose-bound derived credentials for each
other project (a VALKYRJA hardware-attestation cert, an Onna-Bugeisha wallet
identity, a Cytherea Q-Viewer signer) from one root key via HKDF-style
derivation with project-specific context strings — one root identity to
protect and back up, with every other Obsidian Circuit system holding only a
derived, independently-revocable credential. This is the "identity layer
other systems build on" dream made concrete as one derivation mechanism.

**QuantumTrader Pro — explicit non-integration, flagged.** QuantumTrader Pro
is a stated separate trust domain (real money, fiduciary infrastructure).
Any idea connecting OpenKeychain PQC identity/signing to QuantumTrader Pro
(signing trade confirmations, PQ identity for trader authentication) is
recorded here per the skill's no-filtering rule, but explicitly marked as
requiring operator sign-off before any implementation, per her stated
boundary that this system doesn't couple to the Obsidian Circuit projects.

**Determinism-auditor-compatible key-ceremony logs.** The determinism-
auditor agent scans for non-reproducible operations across the portfolio.
OpenKeychain PQC's key-generation ceremony could emit a structured,
deterministic-replay-friendly log (excluding the actual entropy) of every
decision point — algorithm choices, timestamps as explicit inputs rather than
implicit `time.time()` calls — extending that project-wide determinism
discipline into the Android app's own crypto code paths.

**Formalist-verified composite packet encoding.** The hand-built composite/
standalone OpenPGP packet encoding (against the still-evolving
`draft-ietf-openpgp-pqc`) is exactly the kind of protocol-correctness claim
the formalist agent exists to translate into provable statements. Route the
packet encoder/decoder's round-trip property (encode∘decode = identity,
decode rejects all malformed input) through a formal spec or
property-based-fuzzer harness as a standing verification artifact, closing
the "hand-implemented against a still-evolving draft" caveat with something
stronger than manual test vectors.

---

## Phase 3 — cross-pollinated combinations (second wave, still no judgment)

**Molt ceremony (Lens 1) × rite-of-passage UX (Lens 5) × pre-flight
checklist (Lens 6) × functorial migration proof (Lens 3).** A single
coherent feature: destructive primary-key regeneration gets a three-act
ritual UI, gated by an aviation-style externalized checklist, backed by a
machine-checked proof that every certification/trust relationship carried
over structurally intact. Four lenses converging on one high-stakes,
currently-underspecified real feature (the app has no formal "start over
cleanly" flow today).

**Weighted Shamir recovery (Lens 3) × gift-economy vouching (Lens 4) ×
guild custody (Lens 4) × swarm quorum-sensing (Lens 1).** Social recovery
becomes a living social structure, not a one-time ceremony: vouches
accumulate over time as lightweight social signals, weighted shares reflect
real relationship depth, and reconstruction only fires once quorum-sensing
detects a genuine live threshold of willing, reachable holders — turning
"social recovery" from a scary one-shot setup into an ongoing, low-stakes
relationship the app quietly maintains.

**Entropy audit trail (Lens 2) × batch/lot tracking (Lens 6) × VALKYRJA
QRNG root (Lens 7) × Cryptanalytic advisory feed (Lens 7).** A unified
"key provenance" system: every key's permanent record includes its entropy
source, its generating software batch/version, and is automatically
cross-referenced against the operator's own advisory feed — so a future
finding ("algorithm X, generated with RNG source Y, in library version Z,
now suspect") can programmatically flag every affected key in one pass
instead of manual reasoning.

**Crystallographic fingerprint viz (Lens 2) × constellation trust-graph
(Lens 5) × topological trust-graph health (Lens 3).** A single visual
language for "what does trust look like": individual keys render as
crystalline fingerprints (recognizable at a glance, deterministic per key),
and the aggregate graph renders as a constellation whose topological health
(bridges, holes, connectivity) is visually legible — replacing hex strings
and flat contact lists with one coherent, navigable visual system across
both the single-key and whole-graph views.

**Counterpoint composite-signature viz (Lens 5) × interference-pattern
verify feedback (Lens 2) × parse-tree advanced view (Lens 5).** A three-
tier signature-verification UX that scales with the user's sophistication:
casual users see the intuitive "two voices in harmony / interference
pattern," while power users can drill into the literal parse tree of the
composite packet — same underlying verification, three honest
representations at three levels of abstraction.

**Cross-compartment QWAMOS policy (Lens 7) × auction-style token priority
(Lens 4) × ATC conflict projection (Lens 6).** A coherent "multi-key,
multi-device, multi-stakes" operating model for power users: keys live in
explicit compartments, contending operations on a shared hardware token
resolve by user-assigned priority rather than FIFO, and the app proactively
projects conflicts (a work-compartment revocation about to break a
personal-compartment signature chain) before they happen.

---

## Phase 4 — structural patterns and latent directions

**Recurring structural pattern: "state that decays/accumulates rather than
flips."** An unusually large fraction of the strongest ideas above (phase-
transition trust levels, tidal-locking pairing, circadian passphrase cache,
pheromone-trail identity ordering, self-organized-criticality backup
nagging) share one mechanism: **continuous accumulation with a
discontinuous, threshold-gated UI response.** This is a genuine latent
architecture direction independent of any single feature — OpenKeychain
PQC's current UI is almost entirely binary-state (verified/not, cached/not,
trusted/not); a shared "decay/accumulate + threshold" primitive underneath
many features would be more honest to how trust and security actually
behave, and would only need building *once*.

**Recurring structural pattern: "make the invisible property visually
legible."** Crystallographic fingerprints, interference-pattern
verification, woven composite-key visualization, constellation trust
graphs, architectural load-bearing hierarchy — all take an abstract
cryptographic property (this key is different from that one; this
signature matches; this algorithm is hybrid; this graph is healthy; this
subkey is non-critical) and give it a **physically-intuitive visual
grammar**. This suggests a genuine product direction: OpenKeychain PQC as
the OpenPGP client that finally makes cryptographic structure *visible*
rather than requiring literacy in hex and jargon — a real differentiator
from every existing OpenPGP tool, all of which are text-and-hex-first.

**Latent direction: OpenKeychain PQC as a portable trust *root*, not just
a client.** Several Lens 7 ideas (Onna-Bugeisha shared identity, VALKYRJA
QRNG root, HNCP kill-switch gesture) point at something bigger than
feature parity: this app could become the **shared identity root** for the
operator's entire portfolio — the one place a post-quantum identity is
minted and audited, with other apps (a wallet, a hardware platform, a
research tool) *consuming* that identity rather than each rolling their
own. That's a materially different product ambition than "OpenPGP client
with PQC support," and it's the direction the "dream" framing at the top of
this document was actually gesturing at.

**Latent direction: a formal "ceremony" abstraction.** Molt, multi-device
sync ceremonies, clean-room import, and the choreography-notation idea are
all instances of a missing general concept: OpenKeychain PQC has no first-
class notion of a **multi-step, stateful, potentially multi-device
"ceremony"** distinct from an ordinary single-screen flow. Building that
abstraction once (state machine + checklist UI + resumability) would make
every future high-stakes flow cheaper to build and more consistent to use.

**Latent direction: local-only "social" layer without a server.** Gift-
economy vouching, guild custody, informational risk-pooling, and swarm
quorum-sensing all reach for the same missing capability: **lightweight,
strictly peer-to-peer social signal exchange** between OpenKeychain PQC
installs, with zero central infrastructure (consistent with the project's
existing no-phone-home stance). This is a substantial but coherent build:
a small P2P protocol (could even ride over existing key-exchange channels
like QR/NFC) purely for these soft social signals, separate from the
heavyweight formal OpenPGP certification mechanism.

---

## Phase 5 — Triage

Operator opted in to triage on 2026-07-13. Judged on the skill's four axes
(novelty, generativity, latent reach, excitement), plus two axes specific to
this codebase: **buildable today** (no dependency on hardware/protocols that
don't exist yet — VALKYRJA silicon, HNCP, an audited PQC MPC ceremony) and
**invariant-safe** (doesn't weaken a stated security invariant per this
project's own commitments). Grouped by underlying mechanism rather than by
lens, since many ideas across bio/math/social/economic lenses turned out to
be the same feature wearing different metaphors — e.g. "swarm quorum-
sensing," "weighted Shamir," "gift-economy vouching," and "guild custody"
are four skins on one real feature: *social recovery with unequal,
accumulating trust*.

Nothing below is deleted or judged as *bad* — per the skill's discipline,
"park" and "seed vault" preserve optionality, they don't kill an idea.

### Pursue now

Buildable today, no speculative dependency, and each one either serves the
"make cryptographic structure legible" differentiator or generalizes a
pattern this session already proved out with a real shipped fix.

- **The "decay/accumulate + threshold" UI primitive** (Phase 4's top
  structural pattern). Build this once as a shared component and it
  strengthens phase-transition trust levels, tidal-locking device pairing,
  circadian passphrase-cache decay, pheromone-trail identity ordering, and
  self-organized-criticality backup nagging simultaneously — five features
  for one build. Highest leverage-per-effort item in the whole document.
- **Crystallographic fingerprint visualization.** Self-contained, pure
  client-side rendering, no protocol/data-model changes, directly attacks
  the "every OpenPGP client is hex-and-jargon-first" gap identified as this
  fork's potential real differentiator.
- **A formal "ceremony" abstraction** (state machine + checklist UI +
  resumability), built once and reused for: the pre-flight/aviation-style
  checklist before irreversible operations, the molt/regeneration ceremony,
  and any future multi-device setup flow. Directly generalizes the
  discipline that caught and fixed this session's KEM-only-master-key hang
  — this session already demonstrated the value of "make dangerous
  configurations impossible to construct, not just warned-against"; a real
  ceremony abstraction is how that becomes the default pattern instead of a
  one-off fix.
- **Mechanically-impossible dangerous configurations, generalized
  app-wide** (the anesthesia-interlock idea). Not a new feature so much as
  turning this session's actual bug fix into a stated data-model
  discipline: illegal states should be unconstructable, not merely
  UI-filtered.
- **Dry-run load test before a new primary key goes live.** Directly
  descended from the exact bug class this session found and fixed; cheap to
  build, catches the next one before a user hits it instead of after.
- **Algorithm-diversity enforcement for "critical" identities** (require
  ≥2 structurally different signature families). Real, buildable,
  reinforces messaging the app's UI already carries about composite vs.
  standalone algorithms.
- **Entropy/provenance audit trail on every generated key.** Metadata-only,
  buildable with zero new infrastructure today, and specifically sets up
  (without requiring) the VALKYRJA QRNG integration later — provenance
  fields designed now mean that integration is a data-source swap, not a
  schema migration.
- **Weighted/hierarchical Shamir social recovery** (spouse's share outweighs
  acquaintance's). Real, non-speculative cryptography (a genuine
  generalization of Shamir, not a research bet), and a legitimate UX gap in
  every k-of-n recovery scheme today.

### Park (promising, real gap, needs a precursor or its own design pass)

- **Trust-graph topology visualizations** (betweenness heatmap, min-cut
  warning, cycle rank, genus). Valuable, but wants a real trust-graph data
  model exposed in the app first — right now this is closer to a data
  layer that doesn't fully exist yet than a UI layer waiting to be drawn.
- **Molt ceremony, full three-act UI + functorial migration proof.**
  Genuinely one of the strongest single ideas in the document, but
  correctly sequenced *after* the ceremony abstraction above — building it
  standalone first means re-solving the ceremony-state-machine problem once
  more, not once.
- **Local-only peer-to-peer social layer** (vouching, guild custody,
  informational risk-pooling, quorum-sensing recovery). Coherent and
  consistent with the project's no-phone-home stance, but it's a real
  protocol design effort in its own right, not a feature to bolt on —
  deserves its own scoping pass, not a triage-line decision.
- **Onna-Bugeisha shared identity root / cross-project "trust passport."**
  This is the idea that most directly matches the "dream" framing at the
  top of this document, but it's cross-repository: needs coordinated design
  with whatever the Onna-Bugeisha wallet's own key-import format actually
  looks like today, not something OpenKeychain PQC can decide unilaterally.
- **Mechanically-simulated conflict projection** (ATC-style: "revoking this
  subkey will break these 3 past signatures"). Real and useful, but wants
  the audit-trail/provenance work above in place first to have something to
  project against.

### Seed vault (keep for later cross-pollination; hardware-dependent, research-grade, or needs explicit operator sign-off)

- **VALKYRJA QRNG entropy root, HSM-backed key storage, HNCP kill-switch
  propagation.** All genuinely good ideas, all blocked on hardware that
  doesn't exist yet. Revisit when VALKYRJA silicon is real.
- **Multi-party PQC key-generation ceremony (MPC).** Explicitly flagged
  speculative — rests on an audited MPC protocol for these specific PQC
  schemes existing, which is active research, not settled engineering.
- **Soft-guardrail key policies for Cytherea-adjacent use.** Explicitly
  flagged in its own generation pass as being in direct tension with "no
  silently weakening security invariants." Not rejected — but this one
  specifically should never move to "pursue" without the operator deciding
  it, not an agent or a triage pass.
- **Any QuantumTrader Pro integration.** Explicitly requires operator
  sign-off per the stated separate-trust-domain boundary; correctly
  generated per the skill's no-filtering rule, correctly parked here.
- **Reputation/economic mechanisms** (bonding curves, Dutch-auction
  revocation urgency, prediction-market confidence aggregation, mutual-
  credit cross-org trust). Clever, real structural transfers, but each adds
  meaningful complexity for a benefit that's currently a design bet, not a
  demonstrated need — worth revisiting if/when the app has organizational
  users who'd actually hit these problems.
- **Pure metaphor/visualization ideas without a clear mechanism advantage**
  (musical counterpoint, woven-textile visualization, architectural
  cross-section, alchemical transmutation staging, constellation trust
  maps, oral-tradition mnemonic seed phrases). Some genuine UX merit, but
  none is urgent and their value is unproven UX hypothesis rather than a
  gap with evidence behind it. Good seed material for a future frontend-
  design pass, not a build queue.

**One recommendation if you want a single next concrete step:** the
decay/accumulate-plus-threshold UI primitive. It's the highest leverage
item in the document — one build strengthens five other ideas at once — is
fully buildable today with zero new dependencies, and it's a genuine
architectural gap (the app's UI is currently all-binary-state) rather than
a nice-to-have.
