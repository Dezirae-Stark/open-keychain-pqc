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


import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.bcpg.OpaqueSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlDsa65Ed25519;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlDsa65Ed25519ContentVerifierBuilderProvider;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Tests for composite ML-DSA-65+Ed25519 OpenPGP signing (draft-ietf-openpgp-pqc-17, algorithm
 * ID 30): a known-answer test against the draft's own published test vector (independent,
 * byte-for-byte confirmation of wire format and seed-expansion correctness -- see {@link
 * #testKnownAnswerAgainstOfficialDraftTestVector()}), plus a real-keyring round trip through
 * {@link PgpKeyOperation}/{@link CanonicalizedSecretKey}/{@link CanonicalizedPublicKey} using
 * the real {@link PGPSignatureGenerator}/{@link PGPSignature} BC objects (validating the
 * targeted bcpg-fork patches), and negative controls (tampered signature, tampered digest,
 * wrong key).
 * <p>
 * The real end-to-end app-operation-level test ({@code
 * CompositeMlDsa65Ed25519RealOperationSignVerifyTest}) exercises {@link
 * PgpSignEncryptOperation}/{@link PgpDecryptVerifyOperation} directly; this class focuses on
 * the crypto core and its direct plumbing through the Canonicalized* classes and BC's
 * signature-packet object model.
 */
@RunWith(KeychainTestRunner.class)
public class CompositeMlDsa65Ed25519SignVerifyTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        // The draft mandates v6-only keys/signatures for algorithm 30, and requires the
        // composite key to certify its own user ID -- so this is a certify+sign master key,
        // matching the shape of the draft's own test vector (a v6 ML-DSA-65+Ed25519 primary
        // key with a direct-key self-sig and a positive-certification user ID self-sig).
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_DSA_65_ED25519, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("pqc-composite-sign-test <pqc-sign@example.org>");
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

        assertEquals(PublicKeyAlgorithmTags.ML_DSA_65_Ed25519, masterKey.getAlgorithm());
        assertTrue(masterKey.isCompositeMlDsa65Ed25519());
        assertTrue(masterKey.canSign());
        assertTrue(masterKey.canCertify());
        assertTrue("PgpSecurityConstants must not flag algorithm 30 as insecure/unidentified",
                masterKey.isSecure());
    }

    /**
     * Full round trip through the real BC signature-packet object model: build a v6 signature
     * using {@link CanonicalizedSecretKey#getDataSignatureGenerator} (which routes through
     * {@code CompositeMlDsa65Ed25519ContentSignerBuilder} and the bcpg-fork's patched
     * {@code PGPSignatureGenerator#generate()} native-encoding case), then verify it via a real
     * {@link PGPSignature#init}/{@link PGPSignature#verify} call (which routes through {@code
     * CompositeMlDsa65Ed25519ContentVerifierBuilderProvider} and the bcpg-fork's patched
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

        byte[] message = "the OpenKeychain composite ML-DSA-65+Ed25519 round trip works"
                .getBytes("UTF-8");

        PGPSignatureGenerator sigGen = secretKey.getDataSignatureGenerator(
                PgpSecurityConstants.DEFAULT_HASH_ALGORITHM, false, null, null);
        sigGen.update(message);
        PGPSignature signature = sigGen.generate();

        assertEquals("signature packet must be tagged with the composite algorithm ID",
                PublicKeyAlgorithmTags.ML_DSA_65_Ed25519, signature.getKeyAlgorithm());
        assertEquals("signature packet must be v6 (no v4 allowance for this algorithm)",
                6, signature.getVersion());
        assertEquals("raw signature value must be exactly Ed25519(64) || ML-DSA-65(3309) octets",
                CompositeMlDsa65Ed25519.COMPOSITE_SIGNATURE_LEN, signature.getSignature().length);

        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(masterKeyId);

        PGPContentVerifierBuilderProvider verifierBuilderProvider =
                new CompositeMlDsa65Ed25519ContentVerifierBuilderProvider();
        signature.init(verifierBuilderProvider, publicKey.getPublicKey());
        signature.update(message);
        assertTrue("real PGPSignature.verify() must accept the genuine composite signature",
                signature.verify());
    }

    /**
     * Tampered signature bytes must not verify, and a signature over a different message must
     * not verify against this one either -- exercised directly against the composite secret/
     * public key material (mirroring the raw-bytes negative-control style already used by
     * {@code CompositeMlKem768X25519EncryptDecryptTest#testTamperedPkeskIsRejected}), so the
     * check is not confounded by any BC packet-parsing machinery.
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
        byte[] signature = CompositeMlDsa65Ed25519.sign(compositeSecret, dataDigest, new SecureRandom());
        assertTrue("sanity check: the untampered signature must verify",
                CompositeMlDsa65Ed25519.verify(compositePub, dataDigest, signature));

        byte[] tamperedInEddsaPart = signature.clone();
        tamperedInEddsaPart[10] ^= 0x01;
        assertFalse("a bit-flip in the Ed25519 component must be rejected",
                CompositeMlDsa65Ed25519.verify(compositePub, dataDigest, tamperedInEddsaPart));

        byte[] tamperedInMldsaPart = signature.clone();
        tamperedInMldsaPart[100] ^= 0x01;
        assertFalse("a bit-flip in the ML-DSA-65 component must be rejected",
                CompositeMlDsa65Ed25519.verify(compositePub, dataDigest, tamperedInMldsaPart));

        byte[] differentDigest = new byte[32];
        new SecureRandom().nextBytes(differentDigest);
        assertFalse("the signature must not verify over a different dataDigest",
                CompositeMlDsa65Ed25519.verify(compositePub, differentDigest, signature));
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
        byte[] signature = CompositeMlDsa65Ed25519.sign(compositeSecret, dataDigest, new SecureRandom());

        CompositeMlDsa65Ed25519.KeyMaterial unrelatedKey =
                CompositeMlDsa65Ed25519.generateKeyPair(new SecureRandom());

        assertFalse("verifying with an unrelated key's public material must not succeed",
                CompositeMlDsa65Ed25519.verify(unrelatedKey.publicKeyBytes, dataDigest, signature));
    }

    /**
     * Known-answer test against draft-ietf-openpgp-pqc-17's own published test vector
     * ({@code test-vectors/v6-mldsa-65-sample-{pk,signature}.asc} at tag
     * draft-ietf-openpgp-pqc-17): a real, independently-generated v6 ML-DSA-65+Ed25519
     * detached signature (algorithm 30, hash algorithm SHA-256) over the message
     * {@code "Testing\n"}, canonicalized as a CANONICAL_TEXT_DOCUMENT signature (sigType 0x01
     * per RFC9580, i.e. with CRLF line endings) by the fingerprint-{@code
     * a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242} test key.
     * <p>
     * The dataDigest reconstruction below mirrors RFC9580 §5.2.4 / {@code
     * PGPSignatureGenerator#generate()} exactly: {@code SHA256(salt || canonicalizedMessage ||
     * trailer)}, where {@code trailer} is the version/sigType/algorithm/hashAlgorithm header
     * plus the hashed-subpacket area plus the closing version/0xff/length footer -- all taken
     * directly from the fetched signature packet's own bytes (hex constants below), not
     * hand-derived. This is the strongest available verification for this phase: it succeeds
     * only if the composite public-key wire encoding, the dataDigest construction, and {@link
     * CompositeMlDsa65Ed25519#verify}'s AND-combiner all independently match a real foreign
     * implementation's output.
     */
    @Test
    public void testKnownAnswerAgainstOfficialDraftTestVector() throws Exception {
        byte[] edPub = Hex.decode(VECTOR_ED25519_PUB_HEX);
        byte[] mldsaPub = Hex.decode(VECTOR_MLDSA65_PUB_HEX);
        byte[] compositePub = concat(edPub, mldsaPub);
        assertEquals(CompositeMlDsa65Ed25519.COMPOSITE_PUBLIC_KEY_LEN, compositePub.length);

        byte[] hashedSubpacketData = Hex.decode(VECTOR_HASHED_SUBPACKET_DATA_HEX);
        byte[] salt = Hex.decode(VECTOR_SALT_HEX);
        byte[] signature = Hex.decode(VECTOR_SIGNATURE_HEX);
        assertEquals(CompositeMlDsa65Ed25519.COMPOSITE_SIGNATURE_LEN, signature.length);

        int version = 6, sigType = 0x01 /* CANONICAL_TEXT_DOCUMENT */, keyAlgorithm = 30, hashAlgorithm = 8 /* SHA256 */;

        java.io.ByteArrayOutputStream header = new java.io.ByteArrayOutputStream();
        header.write(version);
        header.write(sigType);
        header.write(keyAlgorithm);
        header.write(hashAlgorithm);
        int hlen = hashedSubpacketData.length;
        header.write(hlen >> 24); header.write(hlen >> 16); header.write(hlen >> 8); header.write(hlen);
        header.write(hashedSubpacketData);
        byte[] headerBytes = header.toByteArray();

        java.io.ByteArrayOutputStream trailerOut = new java.io.ByteArrayOutputStream();
        trailerOut.write(headerBytes);
        trailerOut.write(version);
        trailerOut.write(0xff);
        int dlen = headerBytes.length;
        trailerOut.write(dlen >> 24); trailerOut.write(dlen >> 16); trailerOut.write(dlen >> 8); trailerOut.write(dlen);
        byte[] trailer = trailerOut.toByteArray();

        // RFC9580 canonical text document signature: line endings normalized to CRLF.
        byte[] canonicalMessage = "Testing\r\n".getBytes("UTF-8");

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt);
        digest.update(canonicalMessage);
        digest.update(trailer);
        byte[] dataDigest = digest.digest();

        assertTrue("the official draft-ietf-openpgp-pqc-17 test vector signature must verify "
                        + "against its own published public key and message",
                CompositeMlDsa65Ed25519.verify(compositePub, dataDigest, signature));

        // Negative control: this KAT check is not vacuous -- flipping the message, the
        // signature, or the key each independently break verification.
        assertFalse(CompositeMlDsa65Ed25519.verify(compositePub, dataDigest, flipBit(signature, 10)));
        MessageDigest wrongDigestCalc = MessageDigest.getInstance("SHA-256");
        wrongDigestCalc.update(salt);
        wrongDigestCalc.update("Xesting\r\n".getBytes("UTF-8"));
        wrongDigestCalc.update(trailer);
        assertFalse(CompositeMlDsa65Ed25519.verify(compositePub, wrongDigestCalc.digest(), signature));
        assertFalse(CompositeMlDsa65Ed25519.verify(flipBit(compositePub, 40), dataDigest, signature));
    }

    private static byte[] extractCompositeSecretKeyBytes(CanonicalizedSecretKey secretKey) {
        Object secretKeyDataPacket = secretKey.getPrivateKey().getPrivateKeyDataPacket();
        byte[] rawSecretKeyData = ((OpaqueSecretBCPGKey) secretKeyDataPacket).getEncoded();
        return Arrays.copyOf(rawSecretKeyData, CompositeMlDsa65Ed25519.COMPOSITE_SECRET_KEY_LEN);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] flipBit(byte[] in, int offset) {
        byte[] out = in.clone();
        out[offset] ^= 0x01;
        return out;
    }

    // Fetched directly (this session) from raw.githubusercontent.com/openpgp-pqc/draft-openpgp-pqc
    // at tag draft-ietf-openpgp-pqc-17, test-vectors/v6-mldsa-65-sample-pk.asc and
    // v6-mldsa-65-sample-signature.asc; parsed by hand per RFC9580's packet framing rules.

    private static final String VECTOR_ED25519_PUB_HEX =
            "882818406201bb7baeff2bffbe848ce4596c649cc6fdd95ce04c2a1653ae1ab1";

    private static final String VECTOR_MLDSA65_PUB_HEX =
            "b8b7081bfeb551b5a0ff6e49fc01a26d0905fe85021ffbb7ef97a9f2065455c7481f0057b90b806e10dc2f45b237ae98bfbaa03e68ed614dfb65" +
            "9926ddb4df0021b8f51ad26c641cbe980c9300b6a52d7c15f079638a0d7c7b6574b285db86aa9aac8e910c37c3fbc44f63cc34ee5d80fc0d351b" +
            "7490366b0418d914f5ed36765a1b42b94f0e0ad5013543b50c4583d18bd41a2df2d7062e0009d48ae10d3bbc61c22e4641c4c772dfcb2d87edf8" +
            "4c6acccdba824a4fa025e5b07f1eba47d94faebdb66205802fb7494916ac25a339dbdc783d4e3c54aaabce53f4b14a3081be64ff8fe47b1f86c2" +
            "d739648e428698e7ce95501be02463b2b582227991329adf163bc8356eba2f626d76cd50b4c9979314a0163e7fd7ec47479d04bcce337678324b" +
            "743f8badcd6ff01b9631a8c6dc34ecfacab634df6e8152678c8326c9fcf4ee7e2838f85e9d053d7fc85643f4e7505caaaee4d7b72bd72541ae1d" +
            "edc35cef50b85d1658182e2f28c47580d6acd96a11398261e1e68a7a9a5d39a40d80c3d996846d628b6842ab78606112ab6310a3e196c88d44a5" +
            "c454e1eb9822746e771d23e8b4cbbb90e8c2a1c19d22c8410e2cab35db171169483e5eaad7afb629a950908218992f4f3ed9791cbbce97387746" +
            "6f655d07ab4635e5a1b19b60e05221dd051bb0533360070ac7f44cf7f739831b2639e3a43355b1f30444e50bbaae7f579749943510b10f7cb5f6" +
            "f3a0816cd8df03425c670514f7d62fd9c7b9c1e7b371301dfd37a7027378de241fc9fbe49dceab675f1696e8334e6fa1ae68ef2358a9240b3de4" +
            "96f46681ff777e7ee75d1df8bb5f2bb60164ee82d94fd3bcc97a6fb44ca7fd4cb8c1a0b9f0272a95cee3507ce1839db9e6f0c657236f86ae4abe" +
            "76d52133ee3ecb8febf196dd7b25b9781c52c51e49db1d77100b2ea27fb34028f21c404a3b17f01b7a530219d5acd6ddb4e638826aa1007ec7a8" +
            "faf6c3bcd7e91adae0fafbbda9254f91aeb7d3e880a4dd51aa16cb9a5e90a627297caa9b4df8ceeb83389fddee31a8fd434fea854a4cfdbb56ba" +
            "87c0fce9c64cd1c97c9863b7703260f35e29f50cc9de111be4e5cc402f8e70e73a8d53891b616231cfb1a8d053a2290b91614c848b166a7f99fc" +
            "b1d248549c66af6a0cf597d39825e17fb034fac2b46e2363e9e42221adcc3df5564bcdbec309bf87ddedaeac27a33179f76ced85db6e581aaa77" +
            "b9912ea9ab381e9fc6ca5ca028511532f4f31918b8cc9a7f7541acd3d3f624a85bba1c6ef8163104d52b75634ad9f53ee7e783fab1bc47564cc0" +
            "d83f8f45544edf18c968e4b8d6aaa0f46747423355d4c74330c88e87ebb89d3796ee01047523d78105242ddfcaffd892052460db2a10c8d4c94e" +
            "75bb80228cc45a85380f0d2277353836634f1f8af03aed28c89848d87709a9f33c12e5ae19c896b9a8b562d6d1703c0523da88c4ea8ad2f42ab3" +
            "01a524b4b348dddba14e14f094336f6c26439df5ce6c43a7ca18aacaab2954a14ab682f8439ba514d50ecd2616b7845e0d911db06919e54bce08" +
            "e22d204c21f78a63e810e5e4b2d1247dc45172ac2bc8d4b4aae4b24f51b58fb71c68c8d36c7cde57550b1c7fbabf6c3598667b0646968c6a21a4" +
            "af66c424345cce0029f4989e69bf9a784b3072b9ad04d72735d1278c5497d12c984c461c9e2418873b9402a1f67d0c939645b29bca83360472d7" +
            "333000867193c382c37b9e3fe84e3d527a1ce42d752bac88b8a277dc44c6ab6da4b92c8af33e209b13b9ec1fe8c26479e81984009a6c5a41d582" +
            "89b46b3a5264d8d247977dbcf8d69d2768cc8e85d4ee471a5964b7626d9142bb245ad4d4a401abe97529a49bdb45340481a7f5b4c6b1fc5026d5" +
            "e907113fdd12b0bb8f9e631140c42e747d6a37a7e64b2aea3c79ca491fe6d7fd8beabdcb9d16ee6d5ac67318e4989b8ad288be42eaf872248911" +
            "7a2ba7eb8b10e8d7693989d8adf689d21e9e41f84275f70afe147312b18e498ab78b2dca2ab95a5da735c916f9976b8f4ccc10650c1508d3ed58" +
            "706598ae7216be74039630d3286a03693185b1b854e49ae53b254e75f3234520e74d4c8becc1e025cbfa616de275c14765eb94e4b903d729e70d" +
            "fd2ac1f32fe2c656f50ba05df78049fc0849ae2261d16d30ee6f4ae92a75b8a78d29d2fbe97f5fc09c1da81d6938fb1ac2bcf066818d8965b58a" +
            "999d3c4814f2972c56c37d6d216ab5f6d93b723f7dbf9e40280d9d63997a296c9ddcfbbd63d0dc005a3e0bf7fb66e722bac98588afb91d18d307" +
            "d597c9311ad0f6c1070d1431746f93ba2ddc44d99d3387b45996d14acb909f873aedccf37b0706883b83d99f54f4231b5d7841610c839366d4ae" +
            "277107f5c2b962c883ce0e93161f142453e8d6d4d0d62e74190419769bfd7355276f915a854e0a178ef92cb714389893372ebf92f572d5255eac" +
            "4ee11f56951250934fea14e49ff14015102efe1614229d38eab373aa02f6d5a3de3eba8fe88c7e65c72c0bd41db5f4cfa1c9ccd4755eb05b0067" +
            "f5402699804c4b49d2abd135494105c785fda90037671b27e95d4bf653dc79f167db49fc55e1876761623e0ba69fe9c3fb4aa5561e0f3c57b2a6" +
            "40b89419d522f71d292224ec4400c8d16f7ad64a112d3d98774af029195e31926c482786d7107dd54cbce2c4531b8344b1cf122328643208cf7e" +
            "37e6affaf20b14d30bdef25e5914fdadd72d0cac2d03a044b0e2b7f11bff7e3cc388eafd85f9";

    private static final String VECTOR_HASHED_SUBPACKET_DATA_HEX =
            "05826811e6b422a106a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f";

    private static final String VECTOR_SALT_HEX =
            "5f513eef21ab3d771f101e1e35c41977";

    private static final String VECTOR_SIGNATURE_HEX =
            "0204c9fd959e2289c22e68018b3383322d02af35df98f528c30faafbb5e9c157d8ec6b83cafa1e4757d489b116ed57d5dac2fcff1958488abb83" +
            "8f2b10d6bb03f5d6bb071226a0d8d4a99be11066284cfc36780c7ed9263fafe849ecb9f9ee9c28ab2bbeca71a6d48f1d396b77a8925200aa499f" +
            "3b3a21e36535431567f86414b01f445a5c87e4d5693938f64a60b303a5b5f0a9d7cfbacb69bebdae50f9236023345b06e01820ad4a3e560a252e" +
            "337172b721977f5848562981c0ff839ef270b6daf3808ea6ec4e5ab1f6e31bd7547bc44992b32c310583b931298734dfc4aa3085bfe35b4d23d1" +
            "36738dfa03cd05d214cdc231d10e95107e9285025af2b08c9e4be845a507d71991c1b258de2312772238e8446b2a3b5645622eedb2d7c4b66720" +
            "28f0a4ac640327f98616f6394365eaf19e32d29043909167ce5caf4943fa893494af7b340a6ee3622ce32d062ec73d605af98501defc7395eb15" +
            "88f10ea5bf01a56bd76565700942835e716d0293da5b12d2b83797073795aefb2659dff23df88d0a9fb92009a0c9749310724f25e1f8f98ef193" +
            "a780566e6245cc3258e9b90a276539753f69912f90f84977bc345264a253b890a76fc12cb9643d6a31b0b3bffb6b08d929eb0e1fc7068b525abd" +
            "72ff42871d4924b9098d09b2210c48d50ea82f8bc4c5a21574f9340847f0fb3f432fb8e2cac8637047014614c88572b3977e25ee5c07e0a3978b" +
            "3883b98ac174378780a1a8b7f15cdc01b13f110dd3337f18bca12dc05920f5d129fe1ea4022f865cd173e189b204286d1c0d5dc808d37e292b77" +
            "1aeb8043a195083366cabc74c8cc03839b00466f899a0a76058b8f4be7c4b906e455f631cd8efa1a587c3c17a16d8779cfb714988a9d7a51429a" +
            "dbe21a51b045d32a0702e607223d2089fe0ba1fdd8e460f8ff95444d31fc05b17d119ef1c6b3eb544a7c08c15c03aeec1dffcaa32a3f407acafd" +
            "faf88ef296f4d26b9e94f34fa48f912f9c66de9b10562cb54998871f45aec82c1f7f54f684e45b0c5b3e887e10cbe09bc25838c2c5013efd65ff" +
            "48f2794838876b48f683475ec2a37dc2653d6e3fbdabde7ae995ecd608a9e9cb7b66d8cbac93bb6023c0bc1990cb2e60a8ebf0e8cf907d52d3d3" +
            "68e3162ea023ff407b74979781fd3220214c1298b479484b79801748005eb241298420171e64e744580bdc496e4a2463887658566094c0b5d5aa" +
            "76692ef094a9bdc511d42d2928fb3d27e5600ee0c7f4f24432008e6f0c285a0d9cb4e0156433f1d7f02bdf74aeb4c6cebe56640bf0a3c675dd84" +
            "99e3d128eb435ad6e345f795c9348032b0c558cf029bef0af83a07f0308a9079841c7dacaa22d29460feb44715864394d12ecfc6d31f34d82725" +
            "90dc6e389e5b5c344260e2dc97f581c5787290e6aab68f4f858fd3608630ac9dd93c434a5e7496d86ea5f2552c6f297178ae4a8341dac6fa90b1" +
            "0608aa54efc73f4a7f594203cb14ae554c802af1bc6d10702d2988940e320dede04f259b47488814810ea89174ed7e85ff429ae4fa8acd05b7d2" +
            "6775c63aead47ff17b554ea2503e4be894224e1fdb2686788aca92e91b8878577c30c55feb890512d0e73849d7a188809d3e1e525465aa37b39c" +
            "c7f2f78c3a9ec7402cdacadaf40192c45e2c3c0525c392e4fadea3dc13f55367086949ad6e13b3b41b8137d9c39f106190bd96b93d46f3359154" +
            "731729d57127c86a3a67be70095c9ed2596aef6d961af98587c102534d1071ea77464bac70fee516ebcd75cb6e9e797f1c50808a441ff36e9245" +
            "b646ffe90f9be3b3263f7cc6289e51399da5c2e3355786262febdd808528a47a77214009f23f9aac741056ea8da87062237b3b3398300b727312" +
            "4ce52a84faba519ad522d9a46a049906919c49c71358b20ae0d867f8533e784f5cdc84ea0c3247cd1460c509c73acf08a3d10cf08019a2abeb48" +
            "0395043cd8d9ce17424162a286933b004d464c8462a5b704e5d21551c3cb0fced90e5b073618bd1e957522474f926e51fe4c9e66f1ed7a987f73" +
            "3563c5ed2de146e566239606b97fba6196df0029efd2b318751aa1b7a5e42517ba24c45f1bd59d6b0ad14bec638b8d692fff5d9ce0c6745d8147" +
            "c9f5d1f3f4e23557a69efb76897d138a656cde333be7c28fed520912bd81a80676244d22959ef98552f72e11895cfba279d3826eab3c7029b1cf" +
            "a875610101f3b49af5a5031572e7d0c2a67e4df275cc9c5af5e75286768b81c4afaf0e8ce6a41513177f6afab2199af56bd2e5eb8cbf02f3f6bc" +
            "1fd388c1a60957c6c982d9d64cca8493bcfad5922deb766823de1b4a8840cbac385e20e5c1bbe45b7b055b2d037cd2bf3aafc1fbaa55f26c2056" +
            "12e3573db4a84fb7798bfcb4f89c53e5af91752b9071e5f553f1b97d9e4bef73e47076d35d749f6d3b80e46e4a507bec96e1cba867b9339a38d8" +
            "12b793051c453c8927c56759d8a524ae3523847beed7965d8ead0f2bc3285153395ed46d5c614d64e383abb8061ef714a646feb7a79727195e2f" +
            "e2fb807f96beac683f21c574fde78e4299b795ea41eb724cac980896ac3a3a136c483ad13adc1489ede647641a20e26558488964d18eaacd83ea" +
            "3d64315ba90b05bc948b1144d9fdb23c831f9973356aa2bed4660a136d3691c2492cde10acda23f00834b9115bc935f61db229f306b56e30d1cc" +
            "95bca67a0009a09f3c53ba28d12bd061bc88ff381d4017929e9943229ac73432a1df66e5c48fb7d723dc522490633aa0bfe6a53f334d1c74fd21" +
            "c63c7b5e3383d79895526e22e34575ba525ff9daf40d36ba9b5b4582684d8a7265902663d0e24add59b9cfdc688d701470969159064bad204fc8" +
            "073fefa7739cef28f3c679aa8cac1e3db04a2e622da51d3f8cfb691144d652286cd5d7688c152a213c827535a96e95475a92bd093d010f4bb1d3" +
            "6d2a7f72397e947ba135860a6f28ea6ee30f50bb4ccde009ddd819f5c0b69e92fc6da40b7c4d0b4d5c091ed18e05a2c61b90e6b4f61c00644945" +
            "f77d5de866eb02096c662c063c9d483b61a832683d2ebbcd3478b288a3e0202b5159cee339715ffddd902f11dbe94ab049902d71ffbde9ec8b8d" +
            "9fd2f3ca76d8e5fbeace7f1d3928d9c922527f9d70761a682577a4808a444973cb08d20dd4b4568733c231dd254e6cbf76361e95ebad3aac026e" +
            "0ed6662b1cd56d0ca59c5494462d1d8f9775b6b1785558aba4a0c80bcac2a07d840aacd9cbdc142efed42863295a395fb961fa367a421b726e5b" +
            "7e876b61735267e1596c4e8f0b35fe2d23d91fdcf4bac5658bf4e72fa36eca31c5f2c14e22ff5d2f6783708f41257642c60c15814c496dcabdbb" +
            "697bab89ba28305c93aef62cb08f5f8f402f668fbb4ad44a97c9fa2ac74928a9e39124ce2b4ac5f80991c0b6111e539ec2eaa65fea84656fa4cc" +
            "61fab20e4a6374ad881f0c17cbec9db4eed8bd8328c4d8966535fc3c1c2fca803f65cd1b05e3c87f04ccba9fbc72017659712230c014a35996e5" +
            "5b5d4c0e22ced7abce0b4f4ac4884dbc88aeb1a8f6d25a67d2ce780107dd8eb268fc3f1f22983b8f52969836a4dad694e194225776f796d9f50b" +
            "d66b4a17f1a49698b873bbe2ea0244bac2dad8bc15d1b496c8eb0cc99cab0a799c8871ff2e5ed97ee4f9f322159618e74c3aa4b462b0eb71b890" +
            "21361bd5e06890bdd8453a9104731d7606c1f1de7822cdbd75f8401836c7e037851cf4805521afbc1dfa12180fa8ef7677eac0f40570a4845dc3" +
            "fdf3787815a623ee3f65b956aafd7b76c0a644f5dc43ecd16fe1682430c106a57513eacf49fa5321334f31c9803bc0dddcfbba424e2a97ebc471" +
            "7967f3c643067508b8f4fc3c06ab11effba1bf1e704514009654c7bc1109424b9309790030f8b15e8f869c94c7c71b18a8d73b03a28f1b10f11c" +
            "2812f4a48655a69fb69508d395441e32e38919ae476c6dc5410b5134d7d734f12a3cbf9469fdb49042470f36acd38abc6d5a4cb16fd1470171a2" +
            "58f80d6724c1550ebeb122078c5afa53513e25ef2a964f591ecc34a91966c8a6ad1757dfebd6f7987255a37d96ea207b80a6c8a59672133b4ef7" +
            "0595b3c2f984cd596c3a58c44a46c9bf77240610abcf67bffbbf2f4ef3ebbc60b8444dd2183c791149508d79c32e941d5d68dd550f705ff576f3" +
            "7adb8d2e198f140a7eaac162ddd95a660ae1943ebcd502fa1a91dfe7ccea67ee1426bf42232076ddee297f2f6ee56adc239d3b714356e660e44a" +
            "c1bfc32f770093a0018f47d0118d144379c3237c0e00e17be565b7ba5da47f28077f69a80f4c7f646e17d5cdf0570e54827e0700ff7e2e37b8da" +
            "d7e36a48ea6e5bc244cc81a398cc8b0ad4a30b881abd94a9de784a887b31a0a359c09371c0ede9708723426703deeaea5a9970e5c6191cdb2a6a" +
            "97a162d4ad467539912169890b3ee01d4b2afc40a582e8b8a58b5533e417e85253ab21b18928627b5d34ff788381f4283fcaac54c48f6a2d5472" +
            "cec1c3e0d8917d959532d2e07f568ca7da1ca9801559a03c1c88e22f00468426848b40ebcf24a7572dad4dfdeff696c370f2a1af0b9cf1b4915a" +
            "e1d248f2f698d2f487a026df066b2ac7af48be7a9ff6efe0d8d7c6a0e453087979a1d1444d59a65b1ad40a24b869e891a29eda46f32d7f9c5847" +
            "c086e0512a21152b5275798aa6dc676e9fcd76c7cd020a0f132061c5cc000120508089131c2c4953576d9ebcf000000000000000000000000000" +
            "000000080c0f171d27";
}
