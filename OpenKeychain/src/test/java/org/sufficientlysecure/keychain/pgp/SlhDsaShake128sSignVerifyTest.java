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
import org.sufficientlysecure.keychain.pgp.pqc.SlhDsaShake128s;
import org.sufficientlysecure.keychain.pgp.pqc.SlhDsaShake128sContentVerifierBuilderProvider;
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
 * Tests for standalone SLH-DSA-SHAKE-128s OpenPGP signing (draft-ietf-openpgp-pqc-17, algorithm
 * ID 32): a known-answer test against the draft's own published test vector -- fetched directly
 * from {@code raw.githubusercontent.com/openpgp-pqc/draft-openpgp-pqc} at tag
 * {@code draft-ietf-openpgp-pqc-17} -- plus a real-keyring round trip through {@link
 * PgpKeyOperation}/{@link CanonicalizedSecretKey}/{@link CanonicalizedPublicKey} using the real
 * {@link PGPSignatureGenerator}/{@link PGPSignature} BC objects (validating the targeted
 * bcpg-fork patches), and negative controls (tampered signature, tampered digest, wrong key).
 * <p>
 * This is architecturally distinct from every composite class this test pattern was previously
 * applied to ({@code CompositeMlDsa65Ed25519SignVerifyTest}, {@code
 * CompositeMlDsa87Ed448SignVerifyTest}): SLH-DSA has no classical component, no AND-combiner --
 * a single key, a single signature, standing entirely on its own.
 * <p>
 * The real end-to-end app-operation-level test ({@code
 * SlhDsaShake128sRealOperationSignVerifyTest}) exercises {@link PgpSignEncryptOperation}/{@link
 * PgpDecryptVerifyOperation} directly; this class focuses on the crypto core, its direct
 * plumbing through the Canonicalized* classes, and the raw BC packet-parser-level KAT.
 */
@RunWith(KeychainTestRunner.class)
public class SlhDsaShake128sSignVerifyTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        // The draft mandates v6-only keys/signatures for algorithm 32, and requires the key to
        // certify its own user ID -- so this is a certify+sign master key, matching the shape
        // of the draft's own test vector (a v6 SLH-DSA-128s primary key with a direct-key
        // self-sig and a positive-certification user ID self-sig, plus an (unimplemented,
        // algorithm-35) ML-KEM-768+X25519 subkey we don't reproduce here).
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.SLH_DSA_SHAKE_128S, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("pqc-slhdsa-128s-sign-test <pqc-slhdsa-sign@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("SLH-DSA-SHAKE-128s key generation must succeed (this already exercises v6 "
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
     * Canonicalization must not strip the SLH-DSA master key (the exact failure mode the design
     * doc calls out for {@code UncachedKeyRing.KNOWN_ALGORITHMS}), and it must be recognized as
     * signing-capable and secure via the algorithm ID.
     */
    @Test
    public void testCanonicalizationKeepsSlhDsaKey() {
        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = ring.canonicalize(log, 0);
        assertNotNull("canonicalization must succeed (see log: " + log + ")", canonicalized);

        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) canonicalized;
        CanonicalizedPublicKey masterKey = secretRing.getPublicKey(secretRing.getMasterKeyId());

        assertEquals(PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S, masterKey.getAlgorithm());
        assertTrue(masterKey.isSlhDsaShake128s());
        assertTrue(masterKey.canSign());
        assertTrue(masterKey.canCertify());
        assertTrue("PgpSecurityConstants must not flag algorithm 32 as insecure/unidentified",
                masterKey.isSecure());
    }

    /**
     * Full round trip through the real BC signature-packet object model: build a v6 signature
     * using {@link CanonicalizedSecretKey#getDataSignatureGenerator} (which routes through
     * {@code SlhDsaShake128sContentSignerBuilder} and the bcpg-fork's patched {@code
     * PGPSignatureGenerator#generate()} native-encoding case), then verify it via a real {@link
     * PGPSignature#init}/{@link PGPSignature#verify} call (which routes through {@code
     * SlhDsaShake128sContentVerifierBuilderProvider} and the bcpg-fork's patched {@code
     * SignaturePacket} v6 parsing case).
     */
    @Test
    public void testSignatureRoundTripThroughRealPgpSignatureObject() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        assertNotNull(secretRing);
        long masterKeyId = secretRing.getMasterKeyId();

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue("unlocking with the correct passphrase must succeed", secretKey.unlock(PASSPHRASE));

        byte[] message = "the OpenKeychain standalone SLH-DSA-SHAKE-128s round trip works"
                .getBytes("UTF-8");

        PGPSignatureGenerator sigGen = secretKey.getDataSignatureGenerator(
                PgpSecurityConstants.DEFAULT_HASH_ALGORITHM, false, null, null);
        sigGen.update(message);
        PGPSignature signature = sigGen.generate();

        assertEquals("signature packet must be tagged with the SLH-DSA algorithm ID",
                PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S, signature.getKeyAlgorithm());
        assertEquals("signature packet must be v6 (no v4 allowance for this algorithm)",
                6, signature.getVersion());
        assertEquals("raw signature value must be exactly the native SLH-DSA-SHAKE-128s "
                        + "signature octets",
                SlhDsaShake128s.SIGNATURE_LEN, signature.getSignature().length);

        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(masterKeyId);

        PGPContentVerifierBuilderProvider verifierBuilderProvider =
                new SlhDsaShake128sContentVerifierBuilderProvider();
        signature.init(verifierBuilderProvider, publicKey.getPublicKey());
        signature.update(message);
        assertTrue("real PGPSignature.verify() must accept the genuine SLH-DSA signature",
                signature.verify());
    }

    /**
     * Tampered signature bytes must not verify, and a signature over a different digest must
     * not verify against this one either -- exercised directly against the SLH-DSA secret/
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

        byte[] slhDsaSecret = extractSlhDsaSecretKeyBytes(secretKey);
        byte[] slhDsaPub = publicKey.getOpaquePublicKeyMaterial();

        byte[] dataDigest = new byte[32];
        new SecureRandom().nextBytes(dataDigest);
        byte[] signature = SlhDsaShake128s.sign(slhDsaSecret, dataDigest, new SecureRandom());
        assertTrue("sanity check: the untampered signature must verify",
                SlhDsaShake128s.verify(slhDsaPub, dataDigest, signature));

        byte[] tampered = signature.clone();
        tampered[10] ^= 0x01;
        assertFalse("a bit-flip in the SLH-DSA signature must be rejected",
                SlhDsaShake128s.verify(slhDsaPub, dataDigest, tampered));

        byte[] tamperedNearEnd = signature.clone();
        tamperedNearEnd[tamperedNearEnd.length - 1] ^= 0x01;
        assertFalse("a bit-flip near the end of the SLH-DSA signature must be rejected",
                SlhDsaShake128s.verify(slhDsaPub, dataDigest, tamperedNearEnd));

        byte[] differentDigest = new byte[32];
        new SecureRandom().nextBytes(differentDigest);
        assertFalse("the signature must not verify over a different dataDigest",
                SlhDsaShake128s.verify(slhDsaPub, differentDigest, signature));
    }

    /** Verifying with an unrelated key's public material must not succeed. */
    @Test
    public void testWrongKeyCannotVerify() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long masterKeyId = secretRing.getMasterKeyId();
        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue(secretKey.unlock(PASSPHRASE));

        byte[] slhDsaSecret = extractSlhDsaSecretKeyBytes(secretKey);

        byte[] dataDigest = new byte[32];
        new SecureRandom().nextBytes(dataDigest);
        byte[] signature = SlhDsaShake128s.sign(slhDsaSecret, dataDigest, new SecureRandom());

        SlhDsaShake128s.KeyMaterial unrelatedKey = SlhDsaShake128s.generateKeyPair(new SecureRandom());

        assertFalse("verifying with an unrelated key's public material must not succeed",
                SlhDsaShake128s.verify(unrelatedKey.publicKeyBytes, dataDigest, signature));
    }

    /**
     * Negative control on the digest-size floor: the draft mandates rejection of any SLH-DSA
     * signature computed over a sub-256-bit digest. Confirms {@link SlhDsaShake128s#verify}
     * enforces this even when handed a (synthetically shortened) digest and a signature that
     * would otherwise be well-formed.
     */
    @Test
    public void testShortDigestIsRejected() {
        SlhDsaShake128s.KeyMaterial keyMaterial = SlhDsaShake128s.generateKeyPair(new SecureRandom());
        byte[] adequateDigest = new byte[32];
        new SecureRandom().nextBytes(adequateDigest);
        byte[] signature = SlhDsaShake128s.sign(keyMaterial.secretKeyBytes, adequateDigest, new SecureRandom());

        byte[] shortDigest = Arrays.copyOf(adequateDigest, 31);
        assertFalse("a sub-256-bit dataDigest must be rejected outright at verify time",
                SlhDsaShake128s.verify(keyMaterial.publicKeyBytes, shortDigest, signature));
    }

    /**
     * Known-answer test against draft-ietf-openpgp-pqc-17's own published test vector
     * ({@code test-vectors/v6-slhdsa-128s-sample-{pk,signature}.asc} at tag
     * draft-ietf-openpgp-pqc-17, fetched directly from the draft's own git repo): a real,
     * independently-generated v6 SLH-DSA-SHAKE-128s detached signature (algorithm 32) over the
     * message {@code "Testing\n"}, canonicalized as a CANONICAL_TEXT_DOCUMENT signature (sigType
     * 0x01 per RFC9580, i.e. with CRLF line endings) by the fingerprint-{@code
     * eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92} test key.
     * <p>
     * This parses the real vendored test-vector files with the real, patched BC packet parser
     * and verifies through the real {@link PGPSignature#init}/{@link PGPSignature#verify} call
     * path -- exercising {@code PublicKeyPacket}'s and {@code SignaturePacket}'s new
     * algorithm-32 parsing cases directly (public key material length 32, signature length
     * 7856, v6-only enforcement), not just {@link SlhDsaShake128s#verify}. This is the strongest
     * available verification for this phase: it succeeds only if the bcpg-fork's wire parsing,
     * the standalone public-key/signature wire encoding, and {@link SlhDsaShake128s#verify} all
     * independently match a real foreign implementation's output.
     */
    @Test
    public void testKnownAnswerAgainstOfficialDraftTestVector() throws Exception {
        PGPPublicKeyRing officialRing;
        try (InputStream pkIn = PGPUtil.getDecoderStream(
                openTestResource("/test-keys/v6-slhdsa-128s-sample-pk.asc"))) {
            PGPObjectFactory factory = new PGPObjectFactory(pkIn, new JcaKeyFingerprintCalculator());
            officialRing = (PGPPublicKeyRing) factory.nextObject();
        }
        PGPPublicKey officialMasterKey = officialRing.getPublicKey();

        assertEquals("official test vector's primary key must be algorithm 32",
                PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S, officialMasterKey.getAlgorithm());
        assertEquals("official test vector's primary key must be v6",
                6, officialMasterKey.getVersion());
        assertEquals("official test vector's primary key fingerprint must match the draft text",
                "eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92",
                org.bouncycastle.util.encoders.Hex.toHexString(officialMasterKey.getFingerprint()));

        Object keyMaterial = officialMasterKey.getPublicKeyPacket().getKey();
        assertTrue(keyMaterial instanceof OpaquePublicBCPGKey);
        byte[] officialPub = ((OpaquePublicBCPGKey) keyMaterial).getEncoded();
        assertEquals("official public key material must be exactly the native SLH-DSA-SHAKE-128s "
                        + "public key (32 octets, no ECC component)",
                SlhDsaShake128s.PUBLIC_KEY_LEN, officialPub.length);

        PGPSignature officialDetachedSignature;
        try (InputStream sigIn = PGPUtil.getDecoderStream(
                openTestResource("/test-keys/v6-slhdsa-128s-sample-signature.asc"))) {
            PGPObjectFactory factory = new PGPObjectFactory(sigIn, new JcaKeyFingerprintCalculator());
            PGPSignatureList sigList = (PGPSignatureList) factory.nextObject();
            officialDetachedSignature = sigList.get(0);
        }

        assertEquals("official detached signature must be tagged algorithm 32",
                PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S, officialDetachedSignature.getKeyAlgorithm());
        assertEquals("official detached signature must be v6",
                6, officialDetachedSignature.getVersion());
        assertEquals("official detached signature must be exactly the native SLH-DSA-SHAKE-128s "
                        + "signature (7856 octets, no ECC component)",
                SlhDsaShake128s.SIGNATURE_LEN, officialDetachedSignature.getSignature().length);

        // RFC9580 canonical text document signature: line endings normalized to CRLF.
        byte[] canonicalMessage = "Testing\r\n".getBytes("UTF-8");

        PGPContentVerifierBuilderProvider verifierBuilderProvider =
                new SlhDsaShake128sContentVerifierBuilderProvider();
        officialDetachedSignature.init(verifierBuilderProvider, officialMasterKey);
        officialDetachedSignature.update(canonicalMessage);
        assertTrue("the official draft-ietf-openpgp-pqc-17 test vector signature must verify "
                        + "against its own published public key and message, through the real "
                        + "BC PGPSignature object model",
                officialDetachedSignature.verify());

        // Negative control: this KAT check is not vacuous -- a signature over the wrong message
        // must not verify against the same official public key.
        officialDetachedSignature.init(verifierBuilderProvider, officialMasterKey);
        officialDetachedSignature.update("Xesting\r\n".getBytes("UTF-8"));
        assertFalse("the official signature must not verify over a different message",
                officialDetachedSignature.verify());
    }

    private static InputStream openTestResource(String name) {
        InputStream in = SlhDsaShake128sSignVerifyTest.class.getResourceAsStream(name);
        assertNotNull("test resource must be present: " + name, in);
        return in;
    }

    private static byte[] extractSlhDsaSecretKeyBytes(CanonicalizedSecretKey secretKey) {
        Object secretKeyDataPacket = secretKey.getPrivateKey().getPrivateKeyDataPacket();
        byte[] rawSecretKeyData = ((OpaqueSecretBCPGKey) secretKeyDataPacket).getEncoded();
        return Arrays.copyOf(rawSecretKeyData, SlhDsaShake128s.SECRET_KEY_LEN);
    }
}
