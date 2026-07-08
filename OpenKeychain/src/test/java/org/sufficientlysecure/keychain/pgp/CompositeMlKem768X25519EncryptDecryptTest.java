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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlKem768X25519;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * End-to-end round-trip test for composite ML-KEM-768+X25519 OpenPGP encryption
 * (draft-ietf-openpgp-pqc-17, algorithm ID 35): generates a real OpenKeychain keyring with
 * a composite encryption subkey via {@link PgpKeyOperation}, wraps and unwraps a session
 * key through {@link CanonicalizedPublicKey}/{@link CanonicalizedSecretKey}, round-trips
 * the resulting PKESK algorithm-specific data through BC's own {@link
 * PublicKeyEncSessionPacket} wire-format encode/decode (validating the two targeted
 * upstream-BC patches this feature required), and finally uses the recovered session key
 * to actually decrypt a real symmetrically-encrypted message.
 * <p>
 * Everything here exercises real production code paths (the same {@link PgpKeyOperation},
 * {@link CanonicalizedPublicKey}, {@link CanonicalizedSecretKey}, {@link
 * PgpSecurityConstants}, {@link UncachedKeyRing} used by the app) -- not a standalone
 * crypto-only harness.
 */
@RunWith(KeychainTestRunner.class)
public class CompositeMlKem768X25519EncryptDecryptTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        // classical signing/certifying master key -- composite signing (ML-DSA) is phase 3,
        // out of scope here. This master key only ever certifies its own encryption subkey.
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        // the actual subject under test: a composite ML-KEM-768+X25519 encryption subkey.
        // The draft explicitly allows algorithm ID 35 in v4 encryption-capable subkeys
        // (uniquely among the PQC algorithms it defines), so no v6 master key is required.
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_KEM_768_X25519, null, null, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId("pqc-composite-test <pqc@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("composite key generation must succeed: " + result.getLog(), result.success());
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
     * Canonicalization must not strip the composite subkey (the exact failure mode the
     * design doc calls out for {@code UncachedKeyRing.KNOWN_ALGORITHMS}), and the subkey
     * must be recognized as encryption-capable via the composite algorithm ID.
     */
    @Test
    public void testCanonicalizationKeepsCompositeSubkey() {
        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = ring.canonicalize(log, 0);
        assertNotNull("canonicalization must succeed (see log: " + log + ")", canonicalized);

        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) canonicalized;
        long encryptId = getEncryptSubKeyId(secretRing);

        CanonicalizedPublicKey encryptionKey = secretRing.getPublicKey(encryptId);
        assertEquals(PublicKeyAlgorithmTags.ML_KEM_768_X25519, encryptionKey.getAlgorithm());
        assertTrue(encryptionKey.isCompositeMlKem768X25519());
        assertTrue(encryptionKey.canEncrypt());
        assertTrue("PgpSecurityConstants must not flag algorithm 35 as insecure/unidentified",
                encryptionKey.isSecure());
    }

    /**
     * Full round trip: encrypt a real session key to the composite public key via
     * {@link CanonicalizedPublicKey}, decrypt it back via {@link CanonicalizedSecretKey},
     * and confirm the recovered bytes match exactly.
     */
    @Test
    public void testSessionKeyRoundTrip() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        assertNotNull(secretRing);
        long encryptId = getEncryptSubKeyId(secretRing);

        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(encryptId);

        byte[] sessionKey = new byte[32]; // AES-256 content-encryption key
        new SecureRandom().nextBytes(sessionKey);

        byte[] pkeskData = publicKey.encryptSessionKeyMlKem768X25519(
                SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        // expected length: ecdhCipherText(32) + mlkemCipherText(1088) + len(1) + symAlgId(1)
        // + wrapped(32+8) = 32+1088+1+1+40 = 1162
        assertEquals(1162, pkeskData.length);

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue("unlocking with the correct passphrase must succeed", secretKey.unlock(PASSPHRASE));

        byte[] recoveredSessionKey = secretKey.decryptSessionKeyMlKem768X25519(pkeskData, 32);
        assertArrayEquals("recovered session key must match the original exactly",
                sessionKey, recoveredSessionKey);
    }

    /**
     * Validates that the PKESK algorithm-specific bytes we produce are not just internally
     * self-consistent, but survive a genuine round trip through BC's own OpenPGP packet
     * wire format: {@link PublicKeyEncSessionPacket#encode} followed by parsing the encoded
     * bytes back with a fresh {@link BCPGInputStream}. This is the concrete thing the two
     * targeted BC-fork patches ({@code PublicKeyEncSessionPacket}'s parsing switch and
     * {@code PGPSecretKey.extractPrivateKey}'s default case) exist to make possible.
     */
    @Test
    public void testPkeskSurvivesBcPacketWireFormatRoundTrip() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long encryptId = getEncryptSubKeyId(secretRing);
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(encryptId);

        byte[] sessionKey = new byte[32];
        new SecureRandom().nextBytes(sessionKey);
        byte[] pkeskData = publicKey.encryptSessionKeyMlKem768X25519(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        PublicKeyEncSessionPacket pkesk = PublicKeyEncSessionPacket.createV3PKESKPacket(
                encryptId, PublicKeyAlgorithmTags.ML_KEM_768_X25519, new byte[][] { pkeskData });

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(bos);
        pkesk.encode(bcpgOut);
        bcpgOut.close();

        BCPGInputStream bcpgIn = new BCPGInputStream(new ByteArrayInputStream(bos.toByteArray()));
        Packet parsed = bcpgIn.readPacket();
        assertTrue("parsed packet must be a PublicKeyEncSessionPacket",
                parsed instanceof PublicKeyEncSessionPacket);

        PublicKeyEncSessionPacket parsedPkesk = (PublicKeyEncSessionPacket) parsed;
        assertEquals(PublicKeyAlgorithmTags.ML_KEM_768_X25519, parsedPkesk.getAlgorithm());
        assertEquals(encryptId, parsedPkesk.getKeyID());

        byte[][] recoveredData = parsedPkesk.getEncSessionKey();
        assertEquals(1, recoveredData.length);
        assertArrayEquals("PKESK algorithm-specific bytes must survive BC's own encode/decode",
                pkeskData, recoveredData[0]);

        // and the recovered-via-BC-packet-parsing bytes still decrypt correctly
        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue(secretKey.unlock(PASSPHRASE));
        byte[] recoveredSessionKey = secretKey.decryptSessionKeyMlKem768X25519(recoveredData[0], 32);
        assertArrayEquals(sessionKey, recoveredSessionKey);
    }

    /**
     * The recovered session key must actually work: use it to decrypt a real
     * symmetrically-encrypted message (AES-256-CBC, chosen only for test simplicity --
     * production SEIPD framing is out of scope for this composite-KEM-focused test), and
     * confirm the plaintext matches. This is the "generate a message, decrypt it back,
     * plaintext matches" demonstration called for, at the session-key layer this feature
     * actually touches (full SEIPD/AEAD framing is unmodified stock BC/OpenKeychain code,
     * not part of what this feature changes).
     */
    @Test
    public void testRecoveredSessionKeyActuallyDecryptsAMessage() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long encryptId = getEncryptSubKeyId(secretRing);
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(encryptId);

        byte[] sessionKey = new byte[32];
        new SecureRandom().nextBytes(sessionKey);
        byte[] pkeskData = publicKey.encryptSessionKeyMlKem768X25519(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        byte[] plaintext = "the OpenKeychain composite ML-KEM-768+X25519 round trip works"
                .getBytes("UTF-8");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        byte[] ciphertext = aesCbcPkcs7(true, sessionKey, iv, plaintext);

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue(secretKey.unlock(PASSPHRASE));
        byte[] recoveredSessionKey = secretKey.decryptSessionKeyMlKem768X25519(pkeskData, 32);

        byte[] recoveredPlaintext = aesCbcPkcs7(false, recoveredSessionKey, iv, ciphertext);
        assertArrayEquals(plaintext, recoveredPlaintext);
    }

    /** Tampered PKESK bytes must not silently decrypt to a usable key. */
    @Test
    public void testTamperedPkeskIsRejected() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long encryptId = getEncryptSubKeyId(secretRing);
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(encryptId);

        byte[] sessionKey = new byte[32];
        new SecureRandom().nextBytes(sessionKey);
        byte[] pkeskData = publicKey.encryptSessionKeyMlKem768X25519(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        byte[] tampered = pkeskData.clone();
        tampered[tampered.length - 1] ^= (byte) 0xFF; // flip a bit in the wrapped key material

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue(secretKey.unlock(PASSPHRASE));

        try {
            secretKey.decryptSessionKeyMlKem768X25519(tampered, 32);
            fail("tampered PKESK data must be rejected by the RFC 3394 key-wrap integrity check");
        } catch (InvalidCipherTextException expected) {
            // expected: RFC 3394's built-in 64-bit integrity check catches this
        }
    }

    /** Decrypting with an unrelated recipient's secret key must not recover the session key. */
    @Test
    public void testWrongRecipientCannotDecrypt() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long encryptId = getEncryptSubKeyId(secretRing);
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(encryptId);

        byte[] sessionKey = new byte[32];
        new SecureRandom().nextBytes(sessionKey);
        byte[] pkeskData = publicKey.encryptSessionKeyMlKem768X25519(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        CompositeMlKem768X25519.KeyMaterial unrelatedKey =
                CompositeMlKem768X25519.generateKeyPair(new SecureRandom());

        boolean rejectedOrMismatched;
        try {
            byte[] wrongResult = CompositeMlKem768X25519.decryptSessionKey(
                    unrelatedKey.secretKeyBytes, pkeskData, 32);
            rejectedOrMismatched = !java.util.Arrays.equals(sessionKey, wrongResult);
        } catch (InvalidCipherTextException e) {
            rejectedOrMismatched = true;
        }
        assertTrue("decrypting with an unrelated recipient's key must not recover the session key",
                rejectedOrMismatched);
    }

    private static long getEncryptSubKeyId(CanonicalizedSecretKeyRing secretRing) {
        try {
            return secretRing.getEncryptId();
        } catch (Exception e) {
            fail("no valid encryption subkey found on canonicalized ring: " + e);
            throw new AssertionError(e); // unreachable
        }
    }

    private static byte[] aesCbcPkcs7(boolean forEncryption, byte[] key, byte[] iv, byte[] input)
            throws InvalidCipherTextException {
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, out, 0);
        len += cipher.doFinal(out, len);
        byte[] result = new byte[len];
        System.arraycopy(out, 0, result, 0, len);
        return result;
    }
}
