/*
 * Copyright (C) 2026 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.pgp;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.json.JSONObject;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.pqc.SlhDsaShake128s;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.RawKeySeedMaterial;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;

/**
 * Raw PQC key material import: turns a small hex-seed + metadata JSON record into a fresh,
 * self-certified OpenKeychain key built from caller-supplied seed material instead of
 * randomly-generated material.
 * <p>
 * This class owns only the input format (parsing/validation) and the {@link SaveKeyringParcel}
 * assembly. All actual cryptographic work happens in {@link PgpKeyOperation}'s per-algorithm
 * {@code createXxxKeyPairFromSeed} methods and the {@code
 * org.sufficientlysecure.keychain.pgp.pqc.*} algorithm classes' own {@code
 * generateKeyPairFromSeed} methods -- this class does not duplicate any of that, it only builds
 * the {@link SaveKeyringParcel} that drives the existing {@link
 * PgpKeyOperation#createSecretKeyRing} entry point (the same one normal in-app key generation
 * uses).
 *
 * <h3>Input format</h3>
 * One JSON record per key:
 * <pre>{@code
 * {
 *   "algorithm": "ML_DSA_65_ED25519",
 *   "seedHex": "<hex>",
 *   "classicalSeedHex": "<hex>",
 *   "userId": "Imported <foo@bar>"
 * }
 * }</pre>
 * <ul>
 *   <li>{@code algorithm} -- required. Must match a {@link Algorithm} enum constant name
 *       exactly (e.g. {@code ML_KEM_768_X25519}, {@code STANDALONE_ML_DSA_87}). Only the 9 PQC
 *       constants are accepted here -- classical algorithms (RSA/DSA/ELGAMAL/ECDSA/ECDH/EDDSA)
 *       are rejected, since raw seed injection is a PQC-specific feature (classical algorithms
 *       already have their own well-known raw-key-import conventions this class does not
 *       reinvent).</li>
 *   <li>{@code seedHex} -- required, hex-encoded (not base64, matching this codebase's existing
 *       {@link Hex} usage throughout). This is the PQ component's seed for 8 of the 9
 *       algorithms ({@code xi} for ML-DSA, {@code d || z} for ML-KEM) -- but for {@code
 *       SLH_DSA_SHAKE_128S} specifically, FIPS 205 has no compact-seed key generation form (see
 *       {@link SlhDsaShake128s}'s Javadoc), so this field instead carries that algorithm's full
 *       64-octet native secret key encoding. The field is named uniformly across all 9
 *       algorithms for a simpler format rather than singling SLH-DSA out with a differently
 *       named field, but this is a real, disclosed naming imprecision for that one algorithm.</li>
 *   <li>{@code classicalSeedHex} -- required for exactly the 4 composite algorithms ({@code
 *       ML_DSA_65_ED25519}, {@code ML_DSA_87_ED448}, {@code ML_KEM_768_X25519}, {@code
 *       ML_KEM_1024_X448}); must be absent for the 5 standalone algorithms (SLH-DSA and the 4
 *       {@code STANDALONE_*} constants), which have no classical component. Hex-encoded raw
 *       secret key bytes for the classical primitive (Ed25519/Ed448/X25519/X448).</li>
 *   <li>{@code userId} -- optional. If absent, a placeholder ({@link
 *       #DEFAULT_USER_ID}) is synthesized, since OpenPGP certification requires at least one
 *       user ID and there is no way to self-certify a key without one.</li>
 * </ul>
 * There is deliberately no {@code creationTime} field: {@link
 * PgpKeyOperation#createSecretKeyRing} hardcodes {@code new Date()} for the master key's
 * creation time internally and has no caller-supplied override, so a field here would be
 * cosmetic only -- accepting it and silently ignoring it would be exactly the kind of quiet
 * unfaithfulness this codebase's methodology forbids. A future revision that needs a
 * caller-controlled creation time has to change {@code createSecretKeyRing} itself, which this
 * change deliberately does not touch (it is a widely-shared, heavily-tested method with no
 * PQC-specific reason to change here).
 *
 * <h3>Seed/secret-key lengths by algorithm, in octets (hex string length is 2x)</h3>
 * <table>
 *   <caption>classicalSeedHex / seedHex required lengths</caption>
 *   <tr><th>Algorithm</th><th>classicalSeedHex</th><th>seedHex</th></tr>
 *   <tr><td>ML_DSA_65_ED25519</td><td>32 (Ed25519)</td><td>32 (ML-DSA-65 {@code xi})</td></tr>
 *   <tr><td>ML_DSA_87_ED448</td><td>57 (Ed448)</td><td>32 (ML-DSA-87 {@code xi})</td></tr>
 *   <tr><td>ML_KEM_768_X25519</td><td>32 (X25519)</td><td>64 (ML-KEM-768 {@code d||z})</td></tr>
 *   <tr><td>ML_KEM_1024_X448</td><td>56 (X448)</td><td>64 (ML-KEM-1024 {@code d||z})</td></tr>
 *   <tr><td>SLH_DSA_SHAKE_128S</td><td>n/a</td><td>64 (full native secret key, not a seed)</td></tr>
 *   <tr><td>STANDALONE_ML_KEM_768</td><td>n/a</td><td>64</td></tr>
 *   <tr><td>STANDALONE_ML_KEM_1024</td><td>n/a</td><td>64</td></tr>
 *   <tr><td>STANDALONE_ML_DSA_65</td><td>n/a</td><td>32</td></tr>
 *   <tr><td>STANDALONE_ML_DSA_87</td><td>n/a</td><td>32</td></tr>
 * </table>
 *
 * <h3>Known limitation: KEM-only algorithms need a certification-capable master key</h3>
 * ML-KEM (composite and standalone -- {@code ML_KEM_768_X25519}, {@code ML_KEM_1024_X448},
 * {@code STANDALONE_ML_KEM_768}, {@code STANDALONE_ML_KEM_1024}) can never be a certification
 * key: {@link PgpKeyOperation#createSecretKeyRing} requires its first subkey (the master) to
 * carry {@code CERTIFY_OTHER}, but every KEM case in {@code PgpKeyOperation#createKey} rejects
 * {@code CAN_SIGN | CAN_CERTIFY} flags outright -- a pre-existing, unrelated-to-this-change
 * invariant this class does not (and should not) route around. Raw-importing one of these four
 * algorithms therefore also generates a fresh, <b>randomly</b> generated (NOT seed-derived)
 * composite ML-DSA-65+Ed25519 master key to certify it; only the KEM subkey itself is built
 * deterministically from the supplied seed. (A composite PQC signing master is used rather than
 * a plain classical EdDSA one because three of the four KEM-only algorithms are v6-mandatory
 * with no v4 allowance, and a plain EdDSA master built through {@code createSecretKeyRing}'s
 * non-version-aware master-creation path always comes out v4 -- see {@link
 * #buildSaveKeyringParcel}'s inline comment for the full reasoning.) This is surfaced to the
 * caller via {@link ImportResult#syntheticMasterKeyGenerated}, not silently substituted.
 */
public final class RawPqcKeyImport {

    public static final String DEFAULT_USER_ID = "Imported PQC Key <no-uid-provided>";

    private RawPqcKeyImport() {
    }

    /** Thrown for any problem with the input JSON: missing/unknown fields, bad hex, wrong seed
     * length, or a seed field present/absent when it shouldn't be for the given algorithm. This
     * class always rejects clearly rather than silently truncating, padding, or guessing. */
    public static class RawPqcKeyImportException extends Exception {
        public RawPqcKeyImportException(String message) {
            super(message);
        }
    }

    /** A parsed, length-validated raw import request, ready to be turned into a {@link
     * SaveKeyringParcel} by {@link #buildSaveKeyringParcel}. */
    public static class ParsedRequest {
        public final Algorithm algorithm;
        public final byte[] classicalSeed; // null unless a composite algorithm
        public final byte[] pqSeed;
        public final String userId;

        ParsedRequest(Algorithm algorithm, byte[] classicalSeed, byte[] pqSeed, String userId) {
            this.algorithm = algorithm;
            this.classicalSeed = classicalSeed;
            this.pqSeed = pqSeed;
            this.userId = userId;
        }
    }

    /** Result of a successful raw import: the underlying {@link PgpEditKeyResult}, plus
     * whether a synthetic (non-seed-derived) Ed25519 master key had to be generated -- see the
     * class Javadoc's "Known limitation" section for why this happens for KEM-only algorithms. */
    public static class ImportResult {
        public final PgpEditKeyResult editKeyResult;
        public final boolean syntheticMasterKeyGenerated;

        ImportResult(PgpEditKeyResult editKeyResult, boolean syntheticMasterKeyGenerated) {
            this.editKeyResult = editKeyResult;
            this.syntheticMasterKeyGenerated = syntheticMasterKeyGenerated;
        }
    }

    /**
     * Parses and length-validates a raw PQC key import JSON record -- see the class Javadoc for
     * the exact format. Performs no cryptographic work; only decodes hex, checks lengths, and
     * resolves the {@code algorithm} string to an {@link Algorithm} enum constant.
     *
     * @throws RawPqcKeyImportException if the JSON is malformed, the algorithm name is unknown
     *         or not a PQC algorithm, a required field is missing, an inapplicable field is
     *         present, or any hex-decoded seed has the wrong length for its algorithm
     */
    public static ParsedRequest parse(String json) throws RawPqcKeyImportException {
        JSONObject object;
        try {
            object = new JSONObject(json);
        } catch (JSONException e) {
            throw new RawPqcKeyImportException("malformed JSON: " + e.getMessage());
        }

        String algorithmName = object.optString("algorithm", null);
        if (algorithmName == null || algorithmName.isEmpty()) {
            throw new RawPqcKeyImportException("missing required field \"algorithm\"");
        }

        return parseFields(
                algorithmName,
                object.optString("classicalSeedHex", null),
                object.optString("seedHex", null),
                object.optString("userId", null));
    }

    /**
     * Structured-field entry point, sharing all the same validation as {@link #parse}, for
     * callers (like {@code RawPqcKeyImportDialogFragment}) that collect the fields directly
     * from UI widgets rather than a JSON blob -- avoids a pointless JSON-encode-then-decode
     * round trip while keeping exactly one implementation of the validation rules.
     *
     * @param algorithmName must match a {@link Algorithm} enum constant name exactly
     * @param classicalSeedHex hex-encoded classical seed; required (non-null, non-empty) for
     *        composite algorithms, must be null/empty for standalone algorithms
     * @param seedHex hex-encoded PQ seed (or, for SLH-DSA, the full secret key) -- required
     * @param userId optional; {@link #DEFAULT_USER_ID} is synthesized if null/blank
     * @throws RawPqcKeyImportException on any validation failure -- see {@link #parse}
     */
    public static ParsedRequest parseFields(
            String algorithmName, String classicalSeedHex, String seedHex, String userId)
            throws RawPqcKeyImportException {
        if (algorithmName == null || algorithmName.isEmpty()) {
            throw new RawPqcKeyImportException("missing required field \"algorithm\"");
        }
        Algorithm algorithm;
        try {
            algorithm = Algorithm.valueOf(algorithmName);
        } catch (IllegalArgumentException e) {
            throw new RawPqcKeyImportException("unknown \"algorithm\" value: \"" + algorithmName + "\"");
        }
        if (!isPqcAlgorithm(algorithm)) {
            throw new RawPqcKeyImportException(
                    "\"algorithm\" must be one of the 9 PQC algorithms, not a classical algorithm: "
                            + algorithmName);
        }

        if (seedHex == null || seedHex.isEmpty()) {
            throw new RawPqcKeyImportException("missing required field \"seedHex\"");
        }
        byte[] pqSeed = decodeHex("seedHex", seedHex);

        boolean isComposite = isCompositeAlgorithm(algorithm);
        byte[] classicalSeed = null;
        if (isComposite) {
            if (classicalSeedHex == null || classicalSeedHex.isEmpty()) {
                throw new RawPqcKeyImportException(
                        "\"classicalSeedHex\" is required for composite algorithm " + algorithmName);
            }
            classicalSeed = decodeHex("classicalSeedHex", classicalSeedHex);
        } else if (classicalSeedHex != null && !classicalSeedHex.isEmpty()) {
            throw new RawPqcKeyImportException(
                    "\"classicalSeedHex\" must not be present for standalone algorithm " + algorithmName
                            + " (it has no classical component)");
        }

        int expectedClassicalLen = expectedClassicalSeedLen(algorithm);
        if (classicalSeed != null && classicalSeed.length != expectedClassicalLen) {
            throw new RawPqcKeyImportException(String.format(
                    "bad classicalSeedHex length for %s: got %d octets, expected %d",
                    algorithmName, classicalSeed.length, expectedClassicalLen));
        }

        int expectedPqLen = expectedPqSeedLen(algorithm);
        if (pqSeed.length != expectedPqLen) {
            throw new RawPqcKeyImportException(String.format(
                    "bad seedHex length for %s: got %d octets, expected %d",
                    algorithmName, pqSeed.length, expectedPqLen));
        }

        if (userId == null || userId.trim().isEmpty()) {
            userId = DEFAULT_USER_ID;
        }

        return new ParsedRequest(algorithm, classicalSeed, pqSeed, userId);
    }

    private static byte[] decodeHex(String fieldName, String hex) throws RawPqcKeyImportException {
        try {
            return Hex.decodeStrict(hex);
        } catch (RuntimeException e) {
            throw new RawPqcKeyImportException("\"" + fieldName + "\" is not valid hex: " + e.getMessage());
        }
    }

    /** True for exactly the 9 PQC {@link Algorithm} constants (composite and standalone). */
    public static boolean isPqcAlgorithm(Algorithm algorithm) {
        switch (algorithm) {
            case ML_KEM_768_X25519:
            case ML_KEM_1024_X448:
            case ML_DSA_65_ED25519:
            case ML_DSA_87_ED448:
            case SLH_DSA_SHAKE_128S:
            case STANDALONE_ML_KEM_768:
            case STANDALONE_ML_KEM_1024:
            case STANDALONE_ML_DSA_65:
            case STANDALONE_ML_DSA_87:
                return true;
            default:
                return false;
        }
    }

    /** True for the 4 composite (classical + PQ) algorithms; false for the 5 standalone ones. */
    public static boolean isCompositeAlgorithm(Algorithm algorithm) {
        switch (algorithm) {
            case ML_KEM_768_X25519:
            case ML_KEM_1024_X448:
            case ML_DSA_65_ED25519:
            case ML_DSA_87_ED448:
                return true;
            default:
                return false;
        }
    }

    /** True for the 4 KEM (encryption-only) algorithms that can never be a certification/master
     * key -- see the class Javadoc's "Known limitation" section. */
    public static boolean isKemOnlyAlgorithm(Algorithm algorithm) {
        switch (algorithm) {
            case ML_KEM_768_X25519:
            case ML_KEM_1024_X448:
            case STANDALONE_ML_KEM_768:
            case STANDALONE_ML_KEM_1024:
                return true;
            default:
                return false;
        }
    }

    private static int expectedClassicalSeedLen(Algorithm algorithm) {
        switch (algorithm) {
            case ML_DSA_65_ED25519:
                return 32; // Ed25519
            case ML_DSA_87_ED448:
                return 57; // Ed448 (BC's raw encoding length, RFC 8032)
            case ML_KEM_768_X25519:
                return 32; // X25519
            case ML_KEM_1024_X448:
                return 56; // X448
            default:
                return 0; // no classical component
        }
    }

    private static int expectedPqSeedLen(Algorithm algorithm) {
        switch (algorithm) {
            case ML_DSA_65_ED25519:
            case ML_DSA_87_ED448:
            case STANDALONE_ML_DSA_65:
            case STANDALONE_ML_DSA_87:
                return 32; // ML-DSA seed (xi)
            case ML_KEM_768_X25519:
            case ML_KEM_1024_X448:
            case STANDALONE_ML_KEM_768:
            case STANDALONE_ML_KEM_1024:
                return 64; // ML-KEM seed (d || z)
            case SLH_DSA_SHAKE_128S:
                return 64; // full native secret key, not a compact seed -- see class Javadoc
            default:
                throw new IllegalArgumentException("not a PQC algorithm: " + algorithm);
        }
    }

    /** Simple (parcel, syntheticMasterKeyGenerated) pair -- see {@link #buildSaveKeyringParcel}. */
    public static class BuiltParcel {
        public final SaveKeyringParcel parcel;
        public final boolean syntheticMasterKeyGenerated;

        BuiltParcel(SaveKeyringParcel parcel, boolean syntheticMasterKeyGenerated) {
            this.parcel = parcel;
            this.syntheticMasterKeyGenerated = syntheticMasterKeyGenerated;
        }
    }

    /**
     * Builds the {@link SaveKeyringParcel} for a parsed raw import request, ready to be passed
     * to {@link PgpKeyOperation#createSecretKeyRing}. Does not itself call
     * {@code createSecretKeyRing} -- see {@link #importKey} for the one-call convenience path.
     */
    public static BuiltParcel buildSaveKeyringParcel(ParsedRequest request) {
        RawKeySeedMaterial seedMaterial = new RawKeySeedMaterial(request.classicalSeed, request.pqSeed);

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();

        boolean syntheticMasterKeyGenerated = isKemOnlyAlgorithm(request.algorithm);
        if (syntheticMasterKeyGenerated) {
            // KEM algorithms can never carry CERTIFY_OTHER (see class Javadoc) -- a
            // randomly-generated (NOT seed-derived) master certifies the raw-imported KEM
            // subkey instead. This master is itself a composite ML-DSA-65+Ed25519 PQC signing
            // key, not a plain classical EdDSA key: three of the four KEM-only algorithms
            // (ML_KEM_1024_X448, STANDALONE_ML_KEM_768, STANDALONE_ML_KEM_1024) are v6-mandatory
            // with no v4 allowance (see PgpKeyOperation's per-algorithm Javadoc), and a plain
            // EdDSA master built through createSecretKeyRing's public, non-version-aware
            // createKey() overload always comes out v4 -- pairing it with a v6-mandatory KEM
            // subkey would trip UncachedKeyRing#canonicalize's master/subkey version-consistency
            // backstop and fail outright. A v6 PQC signing master sidesteps this for all four
            // KEM algorithms uniformly (including the one, ML_KEM_768_X25519, that would have
            // tolerated a v4 master): a v6 master paired with a v4-allowed algorithm-35 subkey
            // is itself an already-tested-good combination (see
            // V6PrimaryKeyVersionConsistencyTest's "pure-pqc-keyring-test"), since {@code
            // isClassicalAlgorithm} excludes algorithm 35 from that same backstop.
            builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(Algorithm.ML_DSA_65_ED25519, null, null,
                    KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
            builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(request.algorithm, null, null,
                    KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, 0L, seedMaterial));
        } else {
            // Every non-KEM PQC algorithm is signing/certifying-only and can be the master key
            // itself, built deterministically from the supplied seed.
            builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(request.algorithm, null, null,
                    KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L, seedMaterial));
        }
        builder.addUserId(request.userId);

        return new BuiltParcel(builder.build(), syntheticMasterKeyGenerated);
    }

    /**
     * Convenience one-call path: parses {@code json}, builds the {@link SaveKeyringParcel}, and
     * runs it through {@code op.createSecretKeyRing}. Equivalent to calling {@link #parse} then
     * {@link #buildSaveKeyringParcel} then {@code op.createSecretKeyRing} yourself.
     *
     * @throws RawPqcKeyImportException if {@code json} fails to parse or validate -- see
     *         {@link #parse}
     */
    public static ImportResult importKey(PgpKeyOperation op, String json) throws RawPqcKeyImportException {
        ParsedRequest request = parse(json);
        BuiltParcel built = buildSaveKeyringParcel(request);
        PgpEditKeyResult result = op.createSecretKeyRing(built.parcel);
        return new ImportResult(result, built.syntheticMasterKeyGenerated);
    }
}
