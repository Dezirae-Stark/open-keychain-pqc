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

package org.sufficientlysecure.keychain.operations;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.EditKeyResult;
import org.sufficientlysecure.keychain.operations.results.SocialRecoveryReconstructResult;
import org.sufficientlysecure.keychain.operations.results.SocialRecoverySplitResult;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.SocialRecoveryReconstructParcel;
import org.sufficientlysecure.keychain.service.SocialRecoverySplitParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeWeight;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * RealOperation-tier coverage for B7: a real generated keyring, split via
 * {@link SocialRecoverySplitOperation}, reconstructed via {@link SocialRecoveryReconstructOperation}
 * with a qualifying weighted subset of trustee shares, asserting the recovered keyring's master
 * key id matches the original. Also repeats the adversarial insufficient-weight and tampered-share
 * cases at this full-operation level, since checksum verification and fail-closed behavior for
 * the actual app flow live at this layer, not just in the pure WeightedShareSplitterTest core.
 */
@RunWith(KeychainTestRunner.class)
public class SocialRecoveryOperationsTest {

    private static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    @Test
    public void splitAndReconstruct_withQualifyingWeight_recoversTheOriginalKey() throws Exception {
        long masterKeyId = createTestKey("social recovery split test");

        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2), TrusteeWeight.create("Carol", 1));
        SocialRecoverySplitResult splitResult = executeSplit(
                SocialRecoverySplitParcel.create(masterKeyId, trustees, 3));

        assertTrue("split must succeed: " + splitResult.getLog(), splitResult.success());
        assertEquals(3, splitResult.trusteeBundles.size());

        byte[] encryptedBackupBytes = readBackupBytes(splitResult.encryptedBackupUri);

        // Alice (weight 2) + Carol (weight 1) = exactly threshold 3
        List<TrusteeShareBundle> contributed = Arrays.asList(
                splitResult.trusteeBundles.get(0), splitResult.trusteeBundles.get(2));
        SocialRecoveryReconstructResult reconstructResult = executeReconstruct(
                SocialRecoveryReconstructParcel.create(
                        masterKeyId, splitResult.ceremonyId, contributed, encryptedBackupBytes));

        assertTrue("reconstruct must succeed: " + reconstructResult.getLog(), reconstructResult.success());
        assertEquals(Long.valueOf(masterKeyId), reconstructResult.recoveredMasterKeyId);
    }

    @Test
    public void reconstruct_withInsufficientWeight_failsCleanly() throws Exception {
        long masterKeyId = createTestKey("social recovery insufficient weight test");

        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2));
        SocialRecoverySplitResult splitResult = executeSplit(
                SocialRecoverySplitParcel.create(masterKeyId, trustees, 3));
        assertTrue(splitResult.success());

        byte[] encryptedBackupBytes = readBackupBytes(splitResult.encryptedBackupUri);

        // Alice alone: weight 2, one short of threshold 3
        SocialRecoveryReconstructResult reconstructResult = executeReconstruct(
                SocialRecoveryReconstructParcel.create(masterKeyId, splitResult.ceremonyId,
                        Arrays.asList(splitResult.trusteeBundles.get(0)), encryptedBackupBytes));

        assertFalse("reconstruct must fail with insufficient weight", reconstructResult.success());
    }

    @Test
    public void reconstruct_withTamperedShare_failsAtDecryptNotSilently() throws Exception {
        long masterKeyId = createTestKey("social recovery tampered share test");

        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2));
        SocialRecoverySplitResult splitResult = executeSplit(
                SocialRecoverySplitParcel.create(masterKeyId, trustees, 3));
        assertTrue(splitResult.success());

        byte[] encryptedBackupBytes = readBackupBytes(splitResult.encryptedBackupUri);

        TrusteeShareBundle tampered = tamperFirstByte(splitResult.trusteeBundles.get(0));
        SocialRecoveryReconstructResult reconstructResult = executeReconstruct(
                SocialRecoveryReconstructParcel.create(masterKeyId, splitResult.ceremonyId,
                        Arrays.asList(tampered, splitResult.trusteeBundles.get(1)), encryptedBackupBytes));

        assertFalse("a tampered share must be caught by the decrypt step, not silently accepted",
                reconstructResult.success());
    }

    private long createTestKey(String userId) {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId(userId);
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        EditKeyOperation op = new EditKeyOperation(
                RuntimeEnvironment.getApplication(), repository, new ProgressScaler(), new AtomicBoolean());
        EditKeyResult result = op.execute(
                builder.build(), CryptoInputParcel.createCryptoInputParcel(new java.util.Date(), PASSPHRASE));
        assertTrue("test key creation must succeed: " + result.getLog(), result.success());
        return result.mMasterKeyId;
    }

    private SocialRecoverySplitResult executeSplit(SocialRecoverySplitParcel parcel) {
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        SocialRecoverySplitOperation op = new SocialRecoverySplitOperation(
                RuntimeEnvironment.getApplication(), repository, new ProgressScaler(), new AtomicBoolean());
        return op.execute(parcel, CryptoInputParcel.createCryptoInputParcel(PASSPHRASE));
    }

    private SocialRecoveryReconstructResult executeReconstruct(SocialRecoveryReconstructParcel parcel) {
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        SocialRecoveryReconstructOperation op = new SocialRecoveryReconstructOperation(
                RuntimeEnvironment.getApplication(), repository, new ProgressScaler(), new AtomicBoolean());
        return op.execute(parcel, CryptoInputParcel.createCryptoInputParcel());
    }

    private byte[] readBackupBytes(android.net.Uri uri) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (InputStream in = RuntimeEnvironment.getApplication().getContentResolver().openInputStream(uri)) {
            byte[] chunk = new byte[4096];
            int read;
            while ((read = in.read(chunk)) != -1) {
                buffer.write(chunk, 0, read);
            }
        }
        return buffer.toByteArray();
    }

    private static TrusteeShareBundle tamperFirstByte(TrusteeShareBundle bundle) {
        List<byte[]> tamperedBytes = new java.util.ArrayList<>();
        boolean tamperedOne = false;
        for (byte[] shareBytes : bundle.getShareBytes()) {
            byte[] copy = shareBytes.clone();
            if (!tamperedOne) {
                copy[0] ^= 0xFF;
                tamperedOne = true;
            }
            tamperedBytes.add(copy);
        }
        return TrusteeShareBundle.create(bundle.getTrusteeLabel(), bundle.getShareIndices(), tamperedBytes,
                bundle.getMasterKeyId(), bundle.getCeremonyId(), bundle.getThresholdWeight(), bundle.getTotalWeight());
    }
}
