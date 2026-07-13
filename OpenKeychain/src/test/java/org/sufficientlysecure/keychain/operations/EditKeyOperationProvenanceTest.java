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

import java.security.Security;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.BuildConfig;
import org.sufficientlysecure.keychain.Key_metadata;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.EditKeyResult;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Covers B6: EditKeyOperation records generation provenance (app version + entropy source) for
 * a genuinely new key, once, and does not re-record or clobber it on subsequent edits.
 */
@RunWith(KeychainTestRunner.class)
public class EditKeyOperationProvenanceTest {

    private static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    @Test
    public void newKey_recordsProvenance() {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("provenance test");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        EditKeyResult result = execute(builder.build());
        assertTrue("key creation must succeed: " + result.getLog(), result.success());

        Key_metadata metadata = KeyMetadataDao.create(RuntimeEnvironment.getApplication())
                .getKeyMetadata(result.mMasterKeyId);

        assertNotNull("provenance row must exist for a newly-created key", metadata);
        assertEquals(BuildConfig.VERSION_NAME, metadata.getGenerated_by_app_version());
        assertEquals("android_securerandom", metadata.getEntropy_source());
        assertEquals(Long.valueOf(1L), metadata.getProvenance_schema_version());
    }

    @Test
    public void editingAnExistingKey_doesNotOverwriteProvenance() {
        SaveKeyringParcel.Builder createBuilder = SaveKeyringParcel.buildNewKeyringParcel();
        createBuilder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        createBuilder.addUserId("provenance edit target");
        createBuilder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));
        EditKeyResult createResult = execute(createBuilder.build());
        assertTrue(createResult.success());
        long masterKeyId = createResult.mMasterKeyId;

        KeyMetadataDao dao = KeyMetadataDao.create(RuntimeEnvironment.getApplication());
        Key_metadata afterCreate = dao.getKeyMetadata(masterKeyId);
        assertNotNull(afterCreate.getGenerated_by_app_version());

        byte[] fingerprint = KeyWritableRepository.create(RuntimeEnvironment.getApplication())
                .getUnifiedKeyInfo(masterKeyId).fingerprint();
        SaveKeyringParcel.Builder editBuilder = SaveKeyringParcel.buildChangeKeyringParcel(masterKeyId, fingerprint);
        editBuilder.addUserId("second identity");
        EditKeyResult editResult = execute(editBuilder.build());
        assertTrue("edit must succeed: " + editResult.getLog(), editResult.success());

        Key_metadata afterEdit = dao.getKeyMetadata(masterKeyId);
        assertEquals("editing an existing key must not touch its recorded provenance",
                afterCreate.getGenerated_by_app_version(), afterEdit.getGenerated_by_app_version());
        assertEquals(afterCreate.getEntropy_source(), afterEdit.getEntropy_source());
    }

    @Test
    public void neverCreated_hasNoProvenanceRow() {
        Key_metadata metadata = KeyMetadataDao.create(RuntimeEnvironment.getApplication())
                .getKeyMetadata(123456789L);

        assertNull(metadata);
    }

    private EditKeyResult execute(SaveKeyringParcel saveParcel) {
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        EditKeyOperation op = new EditKeyOperation(
                RuntimeEnvironment.getApplication(), repository, new ProgressScaler(), new AtomicBoolean());
        return op.execute(saveParcel, CryptoInputParcel.createCryptoInputParcel(new Date(), PASSPHRASE));
    }
}
