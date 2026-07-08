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


import java.io.InputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.bcpg.OpaquePublicBCPGKey;
import org.bouncycastle.bcpg.OpaqueSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlDsa87Ed448;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlDsa87Ed448ContentVerifierBuilderProvider;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Tests for composite ML-DSA-87+Ed448 OpenPGP signing (draft-ietf-openpgp-pqc-17, algorithm
 * ID 31): a known-answer test against the draft's own published test vector -- fetched directly
 * (this session) from {@code raw.githubusercontent.com/openpgp-pqc/draft-openpgp-pqc} at tag
 * {@code draft-ietf-openpgp-pqc-17}, byte-identical to the copy vendored by Sequoia-PGP's own
 * interop test suite (independently cross-checked with a raw {@code diff} before use) -- plus a
 * real-keyring round trip through {@link PgpKeyOperation}/{@link CanonicalizedSecretKey}/{@link
 * CanonicalizedPublicKey} using the real {@link PGPSignatureGenerator}/{@link PGPSignature} BC
 * objects (validating the targeted bcpg-fork patches), and negative controls (tampered
 * signature, tampered digest, wrong key).
 * <p>
 * Unlike {@code CompositeMlDsa65Ed25519SignVerifyTest}'s KAT check (which reconstructed the
 * v6 {@code dataDigest} by hand from raw hex fields), this class's KAT test parses the real
 * transferable public key and detached signature test vectors with the real, patched BC packet
 * parser ({@link PGPObjectFactory}) and verifies through the real {@link PGPSignature#init}/
 * {@link PGPSignature#verify} call path with {@link CompositeMlDsa87Ed448ContentVerifierBuilderProvider}
 * -- exercising the bcpg-fork's {@code PublicKeyPacket}/{@code SignaturePacket} algorithm-31
 * parsing cases directly, not just the crypto core.
 * <p>
 * The real end-to-end app-operation-level test ({@code
 * CompositeMlDsa87Ed448RealOperationSignVerifyTest}) exercises {@link
 * PgpSignEncryptOperation}/{@link PgpDecryptVerifyOperation} directly; this class focuses on
 * the crypto core, its direct plumbing through the Canonicalized* classes, and the raw BC
 * packet-parser-level KAT.
 */
@RunWith(KeychainTestRunner.class)
public class CompositeMlDsa87Ed448SignVerifyTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        // The draft mandates v6-only keys/signatures for algorithm 31 too (same as 30), and
        // requires the composite key to certify its own user ID -- so this is a certify+sign
        // master key, matching the shape of the draft's own test vector (a v6
        // ML-DSA-87+Ed448 primary key with a direct-key self-sig and a positive-certification
        // user ID self-sig, plus an (unimplemented, algorithm-36) ML-KEM-1024+X448 subkey we
        // don't reproduce here).
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_DSA_87_ED448, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("pqc-composite-sign-test-87 <pqc-sign-87@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("composite key generation must succeed (this already exercises v6 "
                + "self-certification signing): " + result.getLog(), result.success());
        assertNotNull(result.getRing());

        sRing = result.getRing();
    }

    UncachedKeyRing ring;

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;
        ring = sRing;
    }

    /**
     * Canonicalization must not strip the composite master key (the exact failure mode the
     * design doc calls out for {@code UncachedKeyRing.KNOWN_ALGORITHMS}), and it must be
     * recognized as signing-capable and secure via the composite algorithm ID.
     */
    @Test
    public void testCanonicalizationKeepsCompositeKey() {
        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = ring.canonicalize(log, 0);
        assertNotNull("canonicalization must succeed (see log: " + log + ")", canonicalized);

        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) canonicalized;
        CanonicalizedPublicKey masterKey = secretRing.getPublicKey(secretRing.getMasterKeyId());

        assertEquals(PublicKeyAlgorithmTags.ML_DSA_87_Ed448, masterKey.getAlgorithm());
        assertTrue(masterKey.isCompositeMlDsa87Ed448());
        assertTrue(masterKey.canSign());
        assertTrue(masterKey.canCertify());
        assertTrue("PgpSecurityConstants must not flag algorithm 31 as insecure/unidentified",
                masterKey.isSecure());
    }

    /**
     * Full round trip through the real BC signature-packet object model: build a v6 signature
     * using {@link CanonicalizedSecretKey#getDataSignatureGenerator} (which routes through
     * {@code CompositeMlDsa87Ed448ContentSignerBuilder} and the bcpg-fork's patched
     * {@code PGPSignatureGenerator#generate()} native-encoding case), then verify it via a real
     * {@link PGPSignature#init}/{@link PGPSignature#verify} call (which routes through {@code
     * CompositeMlDsa87Ed448ContentVerifierBuilderProvider} and the bcpg-fork's patched
     * {@code SignaturePacket} v6 parsing case).
     */
    @Test
    public void testSignatureRoundTripThroughRealPgpSignatureObject() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        assertNotNull(secretRing);
        long masterKeyId = secretRing.getMasterKeyId();

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue("unlocking with the correct passphrase must succeed", secretKey.unlock(PASSPHRASE));

        byte[] message = "the OpenKeychain composite ML-DSA-87+Ed448 round trip works"
                .getBytes("UTF-8");

        PGPSignatureGenerator sigGen = secretKey.getDataSignatureGenerator(
                PgpSecurityConstants.DEFAULT_HASH_ALGORITHM, false, null, null);
        sigGen.update(message);
        PGPSignature signature = sigGen.generate();

        assertEquals("signature packet must be tagged with the composite algorithm ID",
                PublicKeyAlgorithmTags.ML_DSA_87_Ed448, signature.getKeyAlgorithm());
        assertEquals("signature packet must be v6 (no v4 allowance for this algorithm)",
                6, signature.getVersion());
        assertEquals("raw signature value must be exactly Ed448(114) || ML-DSA-87(4627) octets",
                CompositeMlDsa87Ed448.COMPOSITE_SIGNATURE_LEN, signature.getSignature().length);

        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(masterKeyId);

        PGPContentVerifierBuilderProvider verifierBuilderProvider =
                new CompositeMlDsa87Ed448ContentVerifierBuilderProvider();
        signature.init(verifierBuilderProvider, publicKey.getPublicKey());
        signature.update(message);
        assertTrue("real PGPSignature.verify() must accept the genuine composite signature",
                signature.verify());
    }

    /**
     * Tampered signature bytes must not verify, and a signature over a different message must
     * not verify against this one either -- exercised directly against the composite secret/
     * public key material, so the check is not confounded by any BC packet-parsing machinery.
     */
    @Test
    public void testTamperedSignatureIsRejected() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long masterKeyId = secretRing.getMasterKeyId();
        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue(secretKey.unlock(PASSPHRASE));
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(masterKeyId);

        byte[] compositeSecret = extractCompositeSecretKeyBytes(secretKey);
        byte[] compositePub = publicKey.getOpaquePublicKeyMaterial();

        byte[] dataDigest = new byte[32];
        new SecureRandom().nextBytes(dataDigest);
        byte[] signature = CompositeMlDsa87Ed448.sign(compositeSecret, dataDigest, new SecureRandom());
        assertTrue("sanity check: the untampered signature must verify",
                CompositeMlDsa87Ed448.verify(compositePub, dataDigest, signature));

        byte[] tamperedInEddsaPart = signature.clone();
        tamperedInEddsaPart[10] ^= 0x01;
        assertFalse("a bit-flip in the Ed448 component must be rejected",
                CompositeMlDsa87Ed448.verify(compositePub, dataDigest, tamperedInEddsaPart));

        byte[] tamperedInMldsaPart = signature.clone();
        tamperedInMldsaPart[200] ^= 0x01;
        assertFalse("a bit-flip in the ML-DSA-87 component must be rejected",
                CompositeMlDsa87Ed448.verify(compositePub, dataDigest, tamperedInMldsaPart));

        byte[] differentDigest = new byte[32];
        new SecureRandom().nextBytes(differentDigest);
        assertFalse("the signature must not verify over a different dataDigest",
                CompositeMlDsa87Ed448.verify(compositePub, differentDigest, signature));
    }

    /** Verifying with an unrelated key's public material must not succeed. */
    @Test
    public void testWrongKeyCannotVerify() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long masterKeyId = secretRing.getMasterKeyId();
        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue(secretKey.unlock(PASSPHRASE));

        byte[] compositeSecret = extractCompositeSecretKeyBytes(secretKey);

        byte[] dataDigest = new byte[32];
        new SecureRandom().nextBytes(dataDigest);
        byte[] signature = CompositeMlDsa87Ed448.sign(compositeSecret, dataDigest, new SecureRandom());

        CompositeMlDsa87Ed448.KeyMaterial unrelatedKey =
                CompositeMlDsa87Ed448.generateKeyPair(new SecureRandom());

        assertFalse("verifying with an unrelated key's public material must not succeed",
                CompositeMlDsa87Ed448.verify(unrelatedKey.publicKeyBytes, dataDigest, signature));
    }

    /**
     * Known-answer test against draft-ietf-openpgp-pqc-17's own published test vector
     * ({@code test-vectors/v6-mldsa-87-sample-{pk,signature}.asc} at tag
     * draft-ietf-openpgp-pqc-17, fetched directly this session and independently confirmed
     * byte-identical to the copy vendored in Sequoia-PGP's interop test suite): a real,
     * independently-generated v6 ML-DSA-87+Ed448 detached signature (algorithm 31, hash
     * algorithm SHA3-512) over the message {@code "Testing\n"}, canonicalized as a
     * CANONICAL_TEXT_DOCUMENT signature (sigType 0x01 per RFC9580, i.e. with CRLF line
     * endings) by the fingerprint-{@code
     * 0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20} test key.
     * <p>
     * Unlike {@code CompositeMlDsa65Ed25519SignVerifyTest}'s equivalent KAT (which reconstructs
     * the dataDigest by hand from raw hex fields, verifying only the crypto core in isolation),
     * this test parses the real vendored test-vector files with the real, patched BC packet
     * parser and verifies through the real {@link PGPSignature#init}/{@link
     * PGPSignature#verify} call path -- exercising {@code PublicKeyPacket}'s and {@code
     * SignaturePacket}'s new algorithm-31 parsing cases directly (public key material length
     * 2649, signature length 4741, v6-only enforcement), not just {@link
     * CompositeMlDsa87Ed448#verify}. This is the strongest available verification for this
     * phase: it succeeds only if the bcpg-fork's wire parsing, the composite public-key/
     * signature wire encoding, and {@link CompositeMlDsa87Ed448#verify}'s AND-combiner all
     * independently match a real foreign implementation's output.
     */
    @Test
    public void testKnownAnswerAgainstOfficialDraftTestVector() throws Exception {
        PGPPublicKeyRing officialRing;
        try (InputStream pkIn = PGPUtil.getDecoderStream(
                openTestResource("/test-keys/v6-mldsa-87-sample-pk.asc"))) {
            PGPObjectFactory factory = new PGPObjectFactory(pkIn, new JcaKeyFingerprintCalculator());
            officialRing = (PGPPublicKeyRing) factory.nextObject();
        }
        PGPPublicKey officialMasterKey = officialRing.getPublicKey();

        assertEquals("official test vector's primary key must be algorithm 31",
                PublicKeyAlgorithmTags.ML_DSA_87_Ed448, officialMasterKey.getAlgorithm());
        assertEquals("official test vector's primary key must be v6",
                6, officialMasterKey.getVersion());
        assertEquals("official test vector's primary key fingerprint must match the draft text",
                "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20",
                org.bouncycastle.util.encoders.Hex.toHexString(officialMasterKey.getFingerprint()));

        Object keyMaterial = officialMasterKey.getPublicKeyPacket().getKey();
        assertTrue(keyMaterial instanceof OpaquePublicBCPGKey);
        byte[] officialCompositePub = ((OpaquePublicBCPGKey) keyMaterial).getEncoded();
        assertEquals("official public key material must be exactly Ed448(57) || ML-DSA-87(2592)",
                CompositeMlDsa87Ed448.COMPOSITE_PUBLIC_KEY_LEN, officialCompositePub.length);

        PGPSignature officialDetachedSignature;
        try (InputStream sigIn = PGPUtil.getDecoderStream(
                openTestResource("/test-keys/v6-mldsa-87-sample-signature.asc"))) {
            PGPObjectFactory factory = new PGPObjectFactory(sigIn, new JcaKeyFingerprintCalculator());
            PGPSignatureList sigList = (PGPSignatureList) factory.nextObject();
            officialDetachedSignature = sigList.get(0);
        }

        assertEquals("official detached signature must be tagged algorithm 31",
                PublicKeyAlgorithmTags.ML_DSA_87_Ed448, officialDetachedSignature.getKeyAlgorithm());
        assertEquals("official detached signature must be v6",
                6, officialDetachedSignature.getVersion());
        assertEquals("official detached signature must be exactly Ed448(114) || ML-DSA-87(4627)",
                CompositeMlDsa87Ed448.COMPOSITE_SIGNATURE_LEN, officialDetachedSignature.getSignature().length);

        // RFC9580 canonical text document signature: line endings normalized to CRLF.
        byte[] canonicalMessage = "Testing\r\n".getBytes("UTF-8");

        PGPContentVerifierBuilderProvider verifierBuilderProvider =
                new CompositeMlDsa87Ed448ContentVerifierBuilderProvider();
        officialDetachedSignature.init(verifierBuilderProvider, officialMasterKey);
        officialDetachedSignature.update(canonicalMessage);
        assertTrue("the official draft-ietf-openpgp-pqc-17 test vector signature must verify "
                        + "against its own published public key and message, through the real "
                        + "BC PGPSignature object model",
                officialDetachedSignature.verify());

        // Negative control: this KAT check is not vacuous -- a signature over the wrong
        // message must not verify against the same official public key.
        officialDetachedSignature.init(verifierBuilderProvider, officialMasterKey);
        officialDetachedSignature.update("Xesting\r\n".getBytes("UTF-8"));
        assertFalse("the official signature must not verify over a different message",
                officialDetachedSignature.verify());
    }

    private static InputStream openTestResource(String name) {
        InputStream in = CompositeMlDsa87Ed448SignVerifyTest.class.getResourceAsStream(name);
        assertNotNull("test resource must be present: " + name, in);
        return in;
    }

    private static byte[] extractCompositeSecretKeyBytes(CanonicalizedSecretKey secretKey) {
        Object secretKeyDataPacket = secretKey.getPrivateKey().getPrivateKeyDataPacket();
        byte[] rawSecretKeyData = ((OpaqueSecretBCPGKey) secretKeyDataPacket).getEncoded();
        return Arrays.copyOf(rawSecretKeyData, CompositeMlDsa87Ed448.COMPOSITE_SECRET_KEY_LEN);
    }
}
