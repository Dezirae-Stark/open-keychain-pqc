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
import org.sufficientlysecure.keychain.util.InputData;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * End-to-end round trip for standalone (non-composite, closed-ecosystem) ML-DSA-65
 * (OpenKeychain private-use algorithm ID 102) OpenPGP signing, exercised entirely through the
 * same real, top-level app operation classes a caller of the app actually uses -- {@link
 * PgpSignEncryptOperation#execute} and {@link PgpDecryptVerifyOperation#execute} -- with a
 * keyring persisted in a real {@link KeyWritableRepository}, following exactly the same rigor
 * as {@code CompositeMlDsa65Ed25519RealOperationSignVerifyTest}.
 */
@RunWith(KeychainTestRunner.class)
public class StandaloneMlDsa65RealOperationSignVerifyTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.STANDALONE_ML_DSA_65, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("pqc-standalone-mldsa65-real-op-test <pqc-standalone-real-op@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("standalone ML-DSA-65 key generation must succeed (this already exercises "
                + "v6 self-certification signing): " + result.getLog(), result.success());
        assertNotNull(result.getRing());

        sRing = result.getRing();
    }

    /**
     * Full real-app round trip: persist the standalone keyring exactly the way the app does,
     * sign a literal-data message through {@link PgpSignEncryptOperation#execute}, verify it
     * through {@link PgpDecryptVerifyOperation#execute}, and confirm the signature is reported
     * valid. Then confirms a bit-flip in the wire bytes of the signed message is detected and
     * rejected by the same real verification call path.
     */
    @Test
    public void testRealSignVerifyOperationRoundTrip() throws Exception {
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        repository.saveSecretKeyRing(sRing);

        String plaintext = "the OpenKeychain standalone ML-DSA-65 round trip works end-to-end ☭";
        byte[] signedMessage;

        { // sign via the real PgpSignEncryptOperation, using the standalone master key
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes("UTF-8"));

            PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                    RuntimeEnvironment.getApplication(),
                    KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

            InputData data = new InputData(in, in.available());

            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
            pgpData.setSignatureMasterKeyId(sRing.getMasterKeyId());
            pgpData.setSignatureSubKeyId(sRing.getMasterKeyId());
            pgpData.setCleartextSignature(false);
            pgpData.setDetachedSignature(false);

            PgpSignEncryptResult result = op.execute(pgpData.build(),
                    CryptoInputParcel.createCryptoInputParcel(new Date(), PASSPHRASE), data, out);
            assertTrue("real PgpSignEncryptOperation.execute() must succeed signing with the "
                    + "standalone ML-DSA-65 key: " + result.getLog(), result.success());

            signedMessage = out.toByteArray();
        }

        { // verify via the real PgpDecryptVerifyOperation
            DecryptVerifyResult result = runVerify(signedMessage, plaintext);

            assertTrue("real PgpDecryptVerifyOperation.execute() must succeed verifying the "
                    + "standalone-key-signed message: " + result.getLog(), result.success());
            Assert.assertEquals("decryptionResult should be RESULT_NOT_ENCRYPTED",
                    OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED, result.getDecryptionResult().getResult());
            Assert.assertEquals("signatureResult should be RESULT_VALID_KEY_CONFIRMED",
                    OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED, result.getSignatureResult().getResult());
        }

        { // negative control: a tampered signed message must be rejected, not silently accepted
            byte[] tampered = signedMessage.clone();
            // Flip a bit well past the literal-data/one-pass-signature header, landing inside
            // the trailing signature packet's algorithm-specific (raw ML-DSA-65) data.
            int flipOffset = tampered.length - 200;
            tampered[flipOffset] ^= 0x01;

            DecryptVerifyResult result = runVerify(tampered, null);

            Assert.assertEquals("a bit-flipped standalone signature must be reported invalid, "
                            + "not silently accepted, through the real verify operation",
                    OpenPgpSignatureResult.RESULT_INVALID_SIGNATURE, result.getSignatureResult().getResult());
        }
    }

    private DecryptVerifyResult runVerify(byte[] message, String expectedPlaintextOrNull) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(message);
        InputData data = new InputData(in, in.available());

        PgpDecryptVerifyOperation op = new PgpDecryptVerifyOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder().build();
        DecryptVerifyResult result = op.execute(
                input, CryptoInputParcel.createCryptoInputParcel(), data, out);

        if (expectedPlaintextOrNull != null) {
            Assert.assertArrayEquals("recovered plaintext must match the original exactly, via "
                            + "the real app operation classes end-to-end",
                    expectedPlaintextOrNull.getBytes("UTF-8"), out.toByteArray());
        }
        return result;
    }
}
