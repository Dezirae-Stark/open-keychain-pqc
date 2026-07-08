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

import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.OpaquePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.RawPqcKeyImport.RawPqcKeyImportException;
import org.sufficientlysecure.keychain.util.ProgressScaler;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Real, end-to-end tests for raw PQC key material import (see {@link RawPqcKeyImport}): a
 * hex-encoded seed is turned into an actual, self-certified {@link PgpEditKeyResult} via the
 * exact same {@link PgpKeyOperation#createSecretKeyRing} entry point normal in-app key
 * generation uses, and the resulting public key material is checked against a public key
 * <b>independently re-derived from the same seed using Bouncy Castle's own primitive classes
 * directly</b> -- not by re-calling this codebase's {@code pqc.*} wrapper classes, so this is a
 * real correctness check on the wiring, not just "the wrapper agrees with itself".
 * <p>
 * Covers all 9 PQC algorithms once each (composite ML-KEM-768+X25519/ML-KEM-1024+X448/
 * ML-DSA-65+Ed25519/ML-DSA-87+Ed448, standalone SLH-DSA-SHAKE-128s and the 4
 * {@code STANDALONE_*} algorithms), plus format-validation rejection cases and the
 * KEM-only-algorithm synthetic-master-key behavior documented on {@link RawPqcKeyImport}.
 */
@RunWith(KeychainTestRunner.class)
public class RawPqcKeyImportTest {

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    /** Deterministic, easily-inspectable filler: byte i is {@code (start + i) mod 256}. Not
     * cryptographically meaningful -- these are test fixtures, not real key material. */
    private static String hexPattern(int length, int start) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (start + i);
        }
        return Hex.toHexString(bytes);
    }

    private static PgpEditKeyResult doImport(String json) throws RawPqcKeyImportException {
        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        return RawPqcKeyImport.importKey(op, json).editKeyResult;
    }

    private static byte[] opaquePublicKeyBytes(PGPPublicKey key) {
        Object keyMaterial = key.getPublicKeyPacket().getKey();
        assertTrue("expected an OpaquePublicBCPGKey, got " + keyMaterial.getClass(),
                keyMaterial instanceof OpaquePublicBCPGKey);
        return ((OpaquePublicBCPGKey) keyMaterial).getEncoded();
    }

    // ------------------------------------------------------------------------------------
    // One real, end-to-end, independently-verified test per algorithm.
    // ------------------------------------------------------------------------------------

    @Test
    public void compositeMlDsa65Ed25519_masterKeyMatchesIndependentDerivation() throws Exception {
        String classicalSeedHex = hexPattern(32, 1);
        String pqSeedHex = hexPattern(32, 101);

        String json = "{"
                + "\"algorithm\":\"ML_DSA_65_ED25519\","
                + "\"classicalSeedHex\":\"" + classicalSeedHex + "\","
                + "\"seedHex\":\"" + pqSeedHex + "\","
                + "\"userId\":\"raw-import-mldsa65 <t@example.org>\"}";

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey master = result.getRing().mRing.getPublicKeys().next();
        assertTrue(master.isMasterKey());
        assertEquals(PublicKeyAlgorithmTags.ML_DSA_65_Ed25519, master.getAlgorithm());

        Ed25519PublicKeyParameters edPub =
                new Ed25519PrivateKeyParameters(Hex.decodeStrict(classicalSeedHex)).generatePublicKey();
        MLDSAPublicKeyParameters mldsaPub = new MLDSAPrivateKeyParameters(
                MLDSAParameters.ml_dsa_65, Hex.decodeStrict(pqSeedHex), null).getPublicKeyParameters();
        byte[] expectedPub = concat(edPub.getEncoded(), mldsaPub.getEncoded());

        assertArrayEquals("public key must match independent re-derivation from the same seeds",
                expectedPub, opaquePublicKeyBytes(master));
    }

    @Test
    public void compositeMlDsa87Ed448_masterKeyMatchesIndependentDerivation() throws Exception {
        String classicalSeedHex = hexPattern(57, 2);
        String pqSeedHex = hexPattern(32, 202);

        String json = "{"
                + "\"algorithm\":\"ML_DSA_87_ED448\","
                + "\"classicalSeedHex\":\"" + classicalSeedHex + "\","
                + "\"seedHex\":\"" + pqSeedHex + "\"}"; // no userId -> default synthesized

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey master = result.getRing().mRing.getPublicKeys().next();
        assertEquals(PublicKeyAlgorithmTags.ML_DSA_87_Ed448, master.getAlgorithm());

        Ed448PublicKeyParameters edPub =
                new Ed448PrivateKeyParameters(Hex.decodeStrict(classicalSeedHex)).generatePublicKey();
        MLDSAPublicKeyParameters mldsaPub = new MLDSAPrivateKeyParameters(
                MLDSAParameters.ml_dsa_87, Hex.decodeStrict(pqSeedHex), null).getPublicKeyParameters();
        byte[] expectedPub = concat(edPub.getEncoded(), mldsaPub.getEncoded());

        assertArrayEquals(expectedPub, opaquePublicKeyBytes(master));
    }

    @Test
    public void compositeMlKem768X25519_subkeyMatchesIndependentDerivation_andSyntheticMasterUsed()
            throws Exception {
        String classicalSeedHex = hexPattern(32, 3);
        String pqSeedHex = hexPattern(64, 303);

        String json = "{"
                + "\"algorithm\":\"ML_KEM_768_X25519\","
                + "\"classicalSeedHex\":\"" + classicalSeedHex + "\","
                + "\"seedHex\":\"" + pqSeedHex + "\"}";

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        RawPqcKeyImport.ImportResult importResult = RawPqcKeyImport.importKey(op, json);
        assertTrue("KEM algorithm requires a synthetic (randomly generated) certification master",
                importResult.syntheticMasterKeyGenerated);

        PgpEditKeyResult result = importResult.editKeyResult;
        assertTrue("import must succeed: " + result.getLog(), result.success());

        Iterator<PGPPublicKey> keys = result.getRing().mRing.getPublicKeys();
        PGPPublicKey master = keys.next();
        PGPPublicKey subkey = keys.next();
        assertFalse("exactly two keys expected (synthetic master + raw-imported KEM subkey)",
                keys.hasNext());

        assertTrue(master.isMasterKey());
        assertEquals("synthetic master must be a composite ML-DSA-65+Ed25519 PQC signing key, "
                        + "not derived from any seed (see RawPqcKeyImport's class Javadoc)",
                PublicKeyAlgorithmTags.ML_DSA_65_Ed25519, master.getAlgorithm());
        assertEquals(PublicKeyAlgorithmTags.ML_KEM_768_X25519, subkey.getAlgorithm());

        X25519PublicKeyParameters x25519Pub =
                new X25519PrivateKeyParameters(Hex.decodeStrict(classicalSeedHex)).generatePublicKey();
        MLKEMPublicKeyParameters mlkemPub = new MLKEMPrivateKeyParameters(
                MLKEMParameters.ml_kem_768, Hex.decodeStrict(pqSeedHex)).getPublicKeyParameters();
        byte[] expectedPub = concat(x25519Pub.getEncoded(), mlkemPub.getEncoded());

        assertArrayEquals(expectedPub, opaquePublicKeyBytes(subkey));
    }

    @Test
    public void compositeMlKem1024X448_subkeyMatchesIndependentDerivation() throws Exception {
        String classicalSeedHex = hexPattern(56, 4);
        String pqSeedHex = hexPattern(64, 404);

        String json = "{"
                + "\"algorithm\":\"ML_KEM_1024_X448\","
                + "\"classicalSeedHex\":\"" + classicalSeedHex + "\","
                + "\"seedHex\":\"" + pqSeedHex + "\"}";

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey subkey = secondKey(result);
        assertEquals(PublicKeyAlgorithmTags.ML_KEM_1024_X448, subkey.getAlgorithm());

        X448PublicKeyParameters x448Pub =
                new X448PrivateKeyParameters(Hex.decodeStrict(classicalSeedHex)).generatePublicKey();
        MLKEMPublicKeyParameters mlkemPub = new MLKEMPrivateKeyParameters(
                MLKEMParameters.ml_kem_1024, Hex.decodeStrict(pqSeedHex)).getPublicKeyParameters();
        byte[] expectedPub = concat(x448Pub.getEncoded(), mlkemPub.getEncoded());

        assertArrayEquals(expectedPub, opaquePublicKeyBytes(subkey));
    }

    @Test
    public void slhDsaShake128s_masterKeyMatchesIndependentDerivation() throws Exception {
        // For SLH-DSA specifically, "seedHex" is the full 64-octet native secret key, not a
        // compact seed -- see RawPqcKeyImport's class Javadoc.
        String secretKeyHex = hexPattern(64, 5);

        String json = "{\"algorithm\":\"SLH_DSA_SHAKE_128S\",\"seedHex\":\"" + secretKeyHex + "\"}";

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey master = result.getRing().mRing.getPublicKeys().next();
        assertEquals(PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S, master.getAlgorithm());

        byte[] expectedPub = new SLHDSAPrivateKeyParameters(SLHDSAParameters.shake_128s,
                Hex.decodeStrict(secretKeyHex)).getEncodedPublicKey();

        assertArrayEquals(expectedPub, opaquePublicKeyBytes(master));
    }

    @Test
    public void standaloneMlKem768_subkeyMatchesIndependentDerivation() throws Exception {
        String pqSeedHex = hexPattern(64, 6);
        String json = "{\"algorithm\":\"STANDALONE_ML_KEM_768\",\"seedHex\":\"" + pqSeedHex + "\"}";

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey subkey = secondKey(result);
        assertEquals(PublicKeyAlgorithmTags.EXPERIMENTAL_1, subkey.getAlgorithm());

        MLKEMPublicKeyParameters mlkemPub = new MLKEMPrivateKeyParameters(
                MLKEMParameters.ml_kem_768, Hex.decodeStrict(pqSeedHex)).getPublicKeyParameters();

        assertArrayEquals(mlkemPub.getEncoded(), opaquePublicKeyBytes(subkey));
    }

    @Test
    public void standaloneMlKem1024_subkeyMatchesIndependentDerivation() throws Exception {
        String pqSeedHex = hexPattern(64, 7);
        String json = "{\"algorithm\":\"STANDALONE_ML_KEM_1024\",\"seedHex\":\"" + pqSeedHex + "\"}";

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey subkey = secondKey(result);
        assertEquals(PublicKeyAlgorithmTags.EXPERIMENTAL_2, subkey.getAlgorithm());

        MLKEMPublicKeyParameters mlkemPub = new MLKEMPrivateKeyParameters(
                MLKEMParameters.ml_kem_1024, Hex.decodeStrict(pqSeedHex)).getPublicKeyParameters();

        assertArrayEquals(mlkemPub.getEncoded(), opaquePublicKeyBytes(subkey));
    }

    @Test
    public void standaloneMlDsa65_masterKeyMatchesIndependentDerivation() throws Exception {
        String pqSeedHex = hexPattern(32, 8);
        String json = "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + pqSeedHex + "\"}";

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey master = result.getRing().mRing.getPublicKeys().next();
        assertEquals(PublicKeyAlgorithmTags.EXPERIMENTAL_3, master.getAlgorithm());

        MLDSAPublicKeyParameters mldsaPub = new MLDSAPrivateKeyParameters(
                MLDSAParameters.ml_dsa_65, Hex.decodeStrict(pqSeedHex), null).getPublicKeyParameters();

        assertArrayEquals(mldsaPub.getEncoded(), opaquePublicKeyBytes(master));
    }

    @Test
    public void standaloneMlDsa87_masterKeyMatchesIndependentDerivation() throws Exception {
        String pqSeedHex = hexPattern(32, 9);
        String json = "{\"algorithm\":\"STANDALONE_ML_DSA_87\",\"seedHex\":\"" + pqSeedHex + "\"}";

        PgpEditKeyResult result = doImport(json);
        assertTrue("import must succeed: " + result.getLog(), result.success());

        PGPPublicKey master = result.getRing().mRing.getPublicKeys().next();
        assertEquals(PublicKeyAlgorithmTags.EXPERIMENTAL_4, master.getAlgorithm());

        MLDSAPublicKeyParameters mldsaPub = new MLDSAPrivateKeyParameters(
                MLDSAParameters.ml_dsa_87, Hex.decodeStrict(pqSeedHex), null).getPublicKeyParameters();

        assertArrayEquals(mldsaPub.getEncoded(), opaquePublicKeyBytes(master));
    }

    // ------------------------------------------------------------------------------------
    // Determinism: same seed twice -> identical public key. Different seed -> different key.
    // ------------------------------------------------------------------------------------

    @Test
    public void sameSeedTwice_producesIdenticalPublicKeyAcrossTwoSeparateImports() throws Exception {
        String pqSeedHex = hexPattern(32, 42);
        String json = "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + pqSeedHex + "\"}";

        PgpEditKeyResult first = doImport(json);
        PgpEditKeyResult second = doImport(json);
        assertTrue(first.success());
        assertTrue(second.success());

        byte[] pub1 = opaquePublicKeyBytes(first.getRing().mRing.getPublicKeys().next());
        byte[] pub2 = opaquePublicKeyBytes(second.getRing().mRing.getPublicKeys().next());

        assertArrayEquals("the same seed must always produce the same public key", pub1, pub2);
    }

    @Test
    public void differentSeeds_produceDifferentPublicKeys() throws Exception {
        String jsonA = "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + hexPattern(32, 1) + "\"}";
        String jsonB = "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + hexPattern(32, 99) + "\"}";

        PgpEditKeyResult resultA = doImport(jsonA);
        PgpEditKeyResult resultB = doImport(jsonB);
        assertTrue(resultA.success());
        assertTrue(resultB.success());

        byte[] pubA = opaquePublicKeyBytes(resultA.getRing().mRing.getPublicKeys().next());
        byte[] pubB = opaquePublicKeyBytes(resultB.getRing().mRing.getPublicKeys().next());

        assertFalse("different seeds must not collide to the same public key",
                java.util.Arrays.equals(pubA, pubB));
    }

    // ------------------------------------------------------------------------------------
    // Fingerprint determinism: creationTimeSeconds is the field that actually makes the whole
    // key (not just the raw public-key bytes) reproducible -- see RawPqcKeyImport's class
    // Javadoc, "creationTimeSeconds" bullet. The OpenPGP fingerprint is a hash over the public
    // key packet, which includes creation time, so two imports of the identical seed only ever
    // produce the identical fingerprint if creation time is *also* pinned to the same value.
    // ------------------------------------------------------------------------------------

    @Test
    public void sameSeedAndSameExplicitCreationTime_producesIdenticalFingerprintAcrossTwoSeparateImports()
            throws Exception {
        String pqSeedHex = hexPattern(32, 55);
        long creationTimeSeconds = 1_700_000_000L;
        String json = "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + pqSeedHex + "\","
                + "\"creationTimeSeconds\":" + creationTimeSeconds + "}";

        PgpEditKeyResult first = doImport(json);
        PgpEditKeyResult second = doImport(json);
        assertTrue("first import must succeed: " + first.getLog(), first.success());
        assertTrue("second import must succeed: " + second.getLog(), second.success());

        byte[] fingerprint1 = first.getRing().mRing.getPublicKey().getFingerprint();
        byte[] fingerprint2 = second.getRing().mRing.getPublicKey().getFingerprint();

        assertArrayEquals(
                "the same seed AND the same explicit creation time must always produce the "
                        + "identical fingerprint -- this is the deterministic-backup/recovery "
                        + "use case raw-seed import exists for",
                fingerprint1, fingerprint2);
    }

    @Test
    public void sameSeedButDifferentExplicitCreationTimes_producesDifferentFingerprints() throws Exception {
        String pqSeedHex = hexPattern(32, 66);
        String jsonEarlier = "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + pqSeedHex + "\","
                + "\"creationTimeSeconds\":1600000000}";
        String jsonLater = "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + pqSeedHex + "\","
                + "\"creationTimeSeconds\":1700000000}";

        PgpEditKeyResult earlier = doImport(jsonEarlier);
        PgpEditKeyResult later = doImport(jsonLater);
        assertTrue(earlier.success());
        assertTrue(later.success());

        // The underlying public key material (derived purely from the seed) must be identical --
        // only the creation time (and therefore the fingerprint) differs.
        byte[] pubEarlier = opaquePublicKeyBytes(earlier.getRing().mRing.getPublicKeys().next());
        byte[] pubLater = opaquePublicKeyBytes(later.getRing().mRing.getPublicKeys().next());
        assertArrayEquals("same seed must still produce the same underlying public key material",
                pubEarlier, pubLater);

        byte[] fingerprintEarlier = earlier.getRing().mRing.getPublicKey().getFingerprint();
        byte[] fingerprintLater = later.getRing().mRing.getPublicKey().getFingerprint();

        assertFalse(
                "different explicit creation times for the identical seed must produce different "
                        + "fingerprints -- proving creationTimeSeconds is genuinely wired through "
                        + "to createSecretKeyRing, not silently ignored",
                java.util.Arrays.equals(fingerprintEarlier, fingerprintLater));
    }

    @Test
    public void omittedCreationTimeSeconds_parsesToNull() throws Exception {
        RawPqcKeyImport.ParsedRequest request = RawPqcKeyImport.parse(
                "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + hexPattern(32, 0) + "\"}");
        assertEquals(null, request.creationTimeSeconds);
    }

    @Test
    public void explicitCreationTimeSeconds_parsedIntoRequest() throws Exception {
        RawPqcKeyImport.ParsedRequest request = RawPqcKeyImport.parse(
                "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + hexPattern(32, 0) + "\","
                        + "\"creationTimeSeconds\":1234567890}");
        assertEquals(Long.valueOf(1234567890L), request.creationTimeSeconds);
    }

    @Test
    public void negativeCreationTimeSeconds_rejected() {
        try {
            RawPqcKeyImport.parse("{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\""
                    + hexPattern(32, 0) + "\",\"creationTimeSeconds\":-1}");
            fail("expected RawPqcKeyImportException for negative creationTimeSeconds");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("creationTimeSeconds"));
        }
    }

    // ------------------------------------------------------------------------------------
    // Format validation: reject clearly, don't silently truncate/pad/guess.
    // ------------------------------------------------------------------------------------

    @Test
    public void missingAlgorithm_rejected() {
        try {
            RawPqcKeyImport.parse("{\"seedHex\":\"" + hexPattern(32, 0) + "\"}");
            fail("expected RawPqcKeyImportException");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("algorithm"));
        }
    }

    @Test
    public void unknownAlgorithm_rejected() {
        try {
            RawPqcKeyImport.parse("{\"algorithm\":\"NOT_A_REAL_ALGORITHM\",\"seedHex\":\""
                    + hexPattern(32, 0) + "\"}");
            fail("expected RawPqcKeyImportException");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("NOT_A_REAL_ALGORITHM"));
        }
    }

    @Test
    public void classicalAlgorithm_rejected() {
        try {
            RawPqcKeyImport.parse("{\"algorithm\":\"EDDSA\",\"seedHex\":\"" + hexPattern(32, 0) + "\"}");
            fail("expected RawPqcKeyImportException -- raw seed injection is PQC-only");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("PQC"));
        }
    }

    @Test
    public void missingSeedHex_rejected() {
        try {
            RawPqcKeyImport.parse("{\"algorithm\":\"STANDALONE_ML_DSA_65\"}");
            fail("expected RawPqcKeyImportException");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("seedHex"));
        }
    }

    @Test
    public void wrongSeedLength_rejectedNotTruncated() {
        // 16 octets instead of the required 32 for STANDALONE_ML_DSA_65 -- must be rejected
        // outright, not silently zero-padded or truncated.
        try {
            RawPqcKeyImport.parse("{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\""
                    + hexPattern(16, 0) + "\"}");
            fail("expected RawPqcKeyImportException for wrong seed length");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("32"));
        }
    }

    @Test
    public void missingClassicalSeedForCompositeAlgorithm_rejected() {
        try {
            RawPqcKeyImport.parse("{\"algorithm\":\"ML_DSA_65_ED25519\",\"seedHex\":\""
                    + hexPattern(32, 0) + "\"}");
            fail("expected RawPqcKeyImportException -- classicalSeedHex is required for composite algorithms");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("classicalSeedHex"));
        }
    }

    @Test
    public void unexpectedClassicalSeedForStandaloneAlgorithm_rejected() {
        try {
            RawPqcKeyImport.parse("{\"algorithm\":\"STANDALONE_ML_DSA_65\","
                    + "\"classicalSeedHex\":\"" + hexPattern(32, 0) + "\","
                    + "\"seedHex\":\"" + hexPattern(32, 1) + "\"}");
            fail("expected RawPqcKeyImportException -- standalone algorithms have no classical component");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().contains("classicalSeedHex"));
        }
    }

    @Test
    public void malformedJson_rejected() {
        try {
            RawPqcKeyImport.parse("not json at all");
            fail("expected RawPqcKeyImportException");
        } catch (RawPqcKeyImportException expected) {
            assertTrue(expected.getMessage().toLowerCase().contains("json"));
        }
    }

    @Test
    public void missingUserId_synthesizesDefaultPlaceholder() throws Exception {
        RawPqcKeyImport.ParsedRequest request = RawPqcKeyImport.parse(
                "{\"algorithm\":\"STANDALONE_ML_DSA_65\",\"seedHex\":\"" + hexPattern(32, 0) + "\"}");
        assertEquals(RawPqcKeyImport.DEFAULT_USER_ID, request.userId);
    }

    private static PGPPublicKey secondKey(PgpEditKeyResult result) {
        Iterator<PGPPublicKey> keys = result.getRing().mRing.getPublicKeys();
        keys.next();
        assertTrue("expected at least two keys in the ring", keys.hasNext());
        return keys.next();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
