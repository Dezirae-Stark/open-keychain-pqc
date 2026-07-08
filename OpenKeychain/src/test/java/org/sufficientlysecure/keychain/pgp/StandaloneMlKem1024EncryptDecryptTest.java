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
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlKem1024;
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
 * End-to-end round-trip test for standalone (non-composite, closed-ecosystem) ML-KEM-1024
 * OpenPGP encryption (OpenKeychain private-use algorithm ID 100 -- NOT defined by
 * draft-ietf-openpgp-pqc-17 or any other spec; see
 * docs/superpowers/specs/2026-07-07-pqc-migration-design.md, Standalone Mode section):
 * generates a real OpenKeychain keyring with a standalone encryption subkey via
 * {@link PgpKeyOperation}, wraps and unwraps a session key through
 * {@link CanonicalizedPublicKey}/{@link CanonicalizedSecretKey}, round-trips the resulting
 * PKESK algorithm-specific data through BC's own {@link PublicKeyEncSessionPacket} wire-format
 * encode/decode, and finally uses the recovered session key to actually decrypt a real
 * symmetrically-encrypted message. Mirrors {@code CompositeMlKem768X25519EncryptDecryptTest}
 * structurally, minus every ECDH-related assertion (there is no classical component here).
 */
@RunWith(KeychainTestRunner.class)
public class StandaloneMlKem1024EncryptDecryptTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        // Standalone ML-KEM-1024 (algorithm 101) is v6-only by this codebase's own decision,
        // so the master (certifying) key must also be v6 -- SLH-DSA-SHAKE-128s is used here
        // purely because createStandaloneMlKem1024KeyPair-equivalent key generation
        // (createSlhDsaShake128sKeyPair) always builds a v6 public key packet, not because it
        // has any bearing on the standalone-KEM subkey under test. Mirrors
        // CompositeMlKem1024X448EncryptDecryptTest's master-key choice exactly.
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.SLH_DSA_SHAKE_128S, null, null, KeyFlags.CERTIFY_OTHER, 0L));
        // the actual subject under test: a standalone ML-KEM-1024 encryption subkey.
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.STANDALONE_ML_KEM_1024, null, null, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId("pqc-standalone-mlkem1024-test <pqc-standalone-1024@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("standalone key generation must succeed: " + result.getLog(), result.success());
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
     * Canonicalization must not strip the standalone subkey (the exact failure mode the
     * design doc calls out for {@code UncachedKeyRing.KNOWN_ALGORITHMS}), and the subkey
     * must be recognized as encryption-capable via the private-use algorithm ID.
     */
    @Test
    public void testCanonicalizationKeepsStandaloneSubkey() {
        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = ring.canonicalize(log, 0);
        assertNotNull("canonicalization must succeed (see log: " + log + ")", canonicalized);

        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) canonicalized;
        long encryptId = getEncryptSubKeyId(secretRing);

        CanonicalizedPublicKey encryptionKey = secretRing.getPublicKey(encryptId);
        assertEquals(PublicKeyAlgorithmTags.EXPERIMENTAL_2, encryptionKey.getAlgorithm());
        assertTrue(encryptionKey.isStandaloneMlKem1024());
        assertTrue(encryptionKey.canEncrypt());
        assertTrue("PgpSecurityConstants must not flag algorithm 101 as insecure/unidentified",
                encryptionKey.isSecure());
    }

    /**
     * Full round trip: encrypt a real session key to the standalone public key via
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

        byte[] pkeskData = publicKey.encryptSessionKeyStandaloneMlKem1024(
                SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        // expected length: mlkemCipherText(1568) + len(1) + symAlgId(1) + wrapped(32+8) =
        // 1568+1+1+40 = 1610 -- no ecdhCipherText field at all, unlike the composite case.
        assertEquals(1610, pkeskData.length);

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue("unlocking with the correct passphrase must succeed", secretKey.unlock(PASSPHRASE));

        byte[] recoveredSessionKey = secretKey.decryptSessionKeyStandaloneMlKem1024(pkeskData, 32);
        assertArrayEquals("recovered session key must match the original exactly",
                sessionKey, recoveredSessionKey);
    }

    /**
     * Validates that the PKESK algorithm-specific bytes we produce survive a genuine round
     * trip through BC's own OpenPGP packet wire format.
     */
    @Test
    public void testPkeskSurvivesBcPacketWireFormatRoundTrip() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long encryptId = getEncryptSubKeyId(secretRing);
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(encryptId);

        byte[] sessionKey = new byte[32];
        new SecureRandom().nextBytes(sessionKey);
        byte[] pkeskData = publicKey.encryptSessionKeyStandaloneMlKem1024(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        PublicKeyEncSessionPacket pkesk = PublicKeyEncSessionPacket.createV3PKESKPacket(
                encryptId, PublicKeyAlgorithmTags.EXPERIMENTAL_2, new byte[][] { pkeskData });

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(bos);
        pkesk.encode(bcpgOut);
        bcpgOut.close();

        BCPGInputStream bcpgIn = new BCPGInputStream(new ByteArrayInputStream(bos.toByteArray()));
        Packet parsed = bcpgIn.readPacket();
        assertTrue("parsed packet must be a PublicKeyEncSessionPacket",
                parsed instanceof PublicKeyEncSessionPacket);

        PublicKeyEncSessionPacket parsedPkesk = (PublicKeyEncSessionPacket) parsed;
        assertEquals(PublicKeyAlgorithmTags.EXPERIMENTAL_2, parsedPkesk.getAlgorithm());
        assertEquals(encryptId, parsedPkesk.getKeyID());

        byte[][] recoveredData = parsedPkesk.getEncSessionKey();
        assertEquals(1, recoveredData.length);
        assertArrayEquals("PKESK algorithm-specific bytes must survive BC's own encode/decode",
                pkeskData, recoveredData[0]);

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue(secretKey.unlock(PASSPHRASE));
        byte[] recoveredSessionKey = secretKey.decryptSessionKeyStandaloneMlKem1024(recoveredData[0], 32);
        assertArrayEquals(sessionKey, recoveredSessionKey);
    }

    /**
     * The recovered session key must actually work: use it to decrypt a real
     * symmetrically-encrypted message (AES-256-CBC, chosen only for test simplicity).
     */
    @Test
    public void testRecoveredSessionKeyActuallyDecryptsAMessage() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long encryptId = getEncryptSubKeyId(secretRing);
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(encryptId);

        byte[] sessionKey = new byte[32];
        new SecureRandom().nextBytes(sessionKey);
        byte[] pkeskData = publicKey.encryptSessionKeyStandaloneMlKem1024(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        byte[] plaintext = "the OpenKeychain standalone ML-KEM-1024 round trip works"
                .getBytes("UTF-8");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        byte[] ciphertext = aesCbcPkcs7(true, sessionKey, iv, plaintext);

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue(secretKey.unlock(PASSPHRASE));
        byte[] recoveredSessionKey = secretKey.decryptSessionKeyStandaloneMlKem1024(pkeskData, 32);

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
        byte[] pkeskData = publicKey.encryptSessionKeyStandaloneMlKem1024(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        byte[] tampered = pkeskData.clone();
        tampered[tampered.length - 1] ^= (byte) 0xFF; // flip a bit in the wrapped key material

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(encryptId);
        assertTrue(secretKey.unlock(PASSPHRASE));

        try {
            secretKey.decryptSessionKeyStandaloneMlKem1024(tampered, 32);
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
        byte[] pkeskData = publicKey.encryptSessionKeyStandaloneMlKem1024(SymmetricKeyAlgorithmTags.AES_256, sessionKey);

        StandaloneMlKem1024.KeyMaterial unrelatedKey =
                StandaloneMlKem1024.generateKeyPair(new SecureRandom());

        boolean rejectedOrMismatched;
        try {
            byte[] wrongResult = StandaloneMlKem1024.decryptSessionKey(
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
