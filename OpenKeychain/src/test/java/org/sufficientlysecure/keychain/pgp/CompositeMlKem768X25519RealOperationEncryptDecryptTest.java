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
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.OpenPgpDecryptionResult;
import org.openintents.openpgp.OpenPgpSignatureResult;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.DecryptVerifyResult;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.operations.results.PgpSignEncryptResult;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper.RawPacket;
import org.sufficientlysecure.keychain.util.InputData;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import java.util.Iterator;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * End-to-end round trip for composite ML-KEM-768+X25519 (algorithm ID 35) OpenPGP
 * encryption, exercised entirely through the same real, top-level app operation classes a
 * caller of the app actually uses -- {@link PgpSignEncryptOperation#execute} and {@link
 * PgpDecryptVerifyOperation#execute} -- with a keyring persisted in a real {@link
 * KeyWritableRepository}, not by calling {@link CanonicalizedPublicKey}/{@link
 * CanonicalizedSecretKey}'s composite methods directly.
 * <p>
 * This is the missing link the adversarial review flagged: {@code
 * CompositeMlKem768X25519EncryptDecryptTest} already proved the crypto core and its direct
 * plumbing through {@code CanonicalizedPublicKey}/{@code CanonicalizedSecretKey} work, but
 * neither {@link CanonicalizedPublicKey#getPubKeyEncryptionGenerator} nor {@link
 * CanonicalizedSecretKey#getCachingDecryptorFactory} -- the two methods {@code
 * PgpSignEncryptOperation}/{@code PgpDecryptVerifyOperation} actually call -- routed
 * algorithm 35 through it. This test would have failed with an {@code
 * IllegalArgumentException} ("unknown asymmetric algorithm: 35") from stock BC's {@code
 * PublicKeyKeyEncryptionMethodGenerator} constructor before that wiring existed.
 */
@RunWith(KeychainTestRunner.class)
public class CompositeMlKem768X25519RealOperationEncryptDecryptTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_KEM_768_X25519, null, null, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId("pqc-composite-real-op-test <pqc-real-op@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("composite key generation must succeed: " + result.getLog(), result.success());
        assertNotNull(result.getRing());

        sRing = result.getRing();
    }

    /**
     * Full real-app round trip: persist the composite keyring exactly the way the app does,
     * encrypt through {@link PgpSignEncryptOperation#execute}, decrypt through {@link
     * PgpDecryptVerifyOperation#execute}, and confirm the recovered plaintext matches. Also
     * confirms the on-the-wire PKESK packet is actually tagged with algorithm ID 35, so the
     * assertion isn't vacuously true via some fallback path.
     */
    @Test
    public void testRealSignEncryptDecryptVerifyOperationRoundTrip() throws Exception {
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        repository.saveSecretKeyRing(sRing);

        String plaintext = "the OpenKeychain composite ML-KEM-768+X25519 round trip works end-to-end ☭";
        byte[] ciphertext;

        { // encrypt via the real PgpSignEncryptOperation, targeting the composite subkey
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes("UTF-8"));

            PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                    RuntimeEnvironment.getApplication(),
                    KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

            InputData data = new InputData(in, in.available());

            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
            pgpData.setEncryptionMasterKeyIds(new long[] { sRing.getMasterKeyId() });
            pgpData.setSymmetricEncryptionAlgorithm(
                    PgpSecurityConstants.OpenKeychainSymmetricKeyAlgorithmTags.AES_256);

            PgpSignEncryptResult result = op.execute(pgpData.build(),
                    CryptoInputParcel.createCryptoInputParcel(new Date()), data, out);
            assertTrue("real PgpSignEncryptOperation.execute() must succeed encrypting to the "
                    + "composite key: " + result.getLog(), result.success());

            ciphertext = out.toByteArray();
        }

        { // sanity check: the actual wire bytes must carry a v3 PKESK tagged algorithm 35 --
          // not silently fall back to some other mechanism
            Iterator<RawPacket> packets = KeyringTestingHelper.parseKeyring(ciphertext);
            RawPacket pkeskPacket = packets.next();
            assertEquals("ciphertext must be [PKESK][encrypted data]",
                    PacketTags.SYM_ENC_INTEGRITY_PRO, packets.next().tag);
            Assert.assertFalse("no further packets", packets.hasNext());

            Packet parsed = new BCPGInputStream(new ByteArrayInputStream(pkeskPacket.buf)).readPacket();
            assertTrue("first packet must be a PublicKeyEncSessionPacket",
                    parsed instanceof PublicKeyEncSessionPacket);
            PublicKeyEncSessionPacket pkesk = (PublicKeyEncSessionPacket) parsed;
            assertEquals("PKESK must be tagged with composite ML-KEM-768+X25519 algorithm ID",
                    PublicKeyAlgorithmTags.ML_KEM_768_X25519, pkesk.getAlgorithm());
        }

        { // decrypt via the real PgpDecryptVerifyOperation, providing the passphrase directly
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
            InputData data = new InputData(in, in.available());

            PgpDecryptVerifyOperation op = new PgpDecryptVerifyOperation(
                    RuntimeEnvironment.getApplication(),
                    KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
            PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder().build();
            DecryptVerifyResult result = op.execute(
                    input, CryptoInputParcel.createCryptoInputParcel(PASSPHRASE), data, out);

            assertTrue("real PgpDecryptVerifyOperation.execute() must succeed decrypting the "
                    + "composite-key-encrypted message: " + result.getLog(), result.success());
            assertArrayEquals("recovered plaintext must match the original exactly, via the "
                            + "real app operation classes end-to-end",
                    plaintext.getBytes("UTF-8"), out.toByteArray());
            assertEquals("decryptionResult should be RESULT_ENCRYPTED",
                    OpenPgpDecryptionResult.RESULT_ENCRYPTED, result.getDecryptionResult().getResult());
            assertEquals("signatureResult should be RESULT_NO_SIGNATURE",
                    OpenPgpSignatureResult.RESULT_NO_SIGNATURE, result.getSignatureResult().getResult());
        }
    }
}
