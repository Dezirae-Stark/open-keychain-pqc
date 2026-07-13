/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;
import androidx.annotation.NonNull;

import org.openintents.openpgp.OpenPgpSignatureResult;
import org.sufficientlysecure.keychain.BuildConfig;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.daos.KeyMetadataDao;
import org.sufficientlysecure.keychain.daos.KeyRepository.NotFoundException;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.operations.results.DecryptVerifyResult;
import org.sufficientlysecure.keychain.operations.results.EditKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.operations.results.PgpSignEncryptResult;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.operations.results.UploadResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKeyRing;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyInputParcel;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyOperation;
import org.sufficientlysecure.keychain.pgp.PgpKeyOperation;
import org.sufficientlysecure.keychain.pgp.PgpSignEncryptData;
import org.sufficientlysecure.keychain.pgp.PgpSignEncryptOperation;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.UploadKeyringParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.service.input.RequiredInputParcel;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;
import org.sufficientlysecure.keychain.util.InputData;
import org.sufficientlysecure.keychain.util.ProgressScaler;

/**
 * An operation which implements a high level key edit operation.
 * <p/>
 * This operation provides a higher level interface to the edit and
 * create key operations in PgpKeyOperation. It takes care of fetching
 * and saving the key before and after the operation.
 *
 * @see SaveKeyringParcel
 *
 */
public class EditKeyOperation extends BaseReadWriteOperation<SaveKeyringParcel> {
    // Fixed today since no second entropy source exists yet; the key_metadata schema is
    // intentionally ready for a future VALKYRJA QRNG value without a further migration.
    private static final String ENTROPY_SOURCE_ANDROID_SECURERANDOM = "android_securerandom";

    private final KeyMetadataDao keyMetadataDao;


    public EditKeyOperation(Context context, KeyWritableRepository databaseInteractor,
                            Progressable progressable, AtomicBoolean cancelled) {
        super(context, databaseInteractor, progressable, cancelled);

        this.keyMetadataDao = KeyMetadataDao.create(context);
    }

    /**
     * Saves an edited key, and uploads it to a server atomically or otherwise as
     * specified in saveParcel
     *
     * @param saveParcel  primary input to the operation
     * @param cryptoInput input that changes if user interaction is required
     * @return the result of the operation
     */
    @NonNull
    public EditKeyResult execute(SaveKeyringParcel saveParcel, CryptoInputParcel cryptoInput) {

        OperationLog log = new OperationLog();
        log.add(LogType.MSG_ED, 0);

        if (saveParcel == null) {
            log.add(LogType.MSG_ED_ERROR_NO_PARCEL, 1);
            return new EditKeyResult(EditKeyResult.RESULT_ERROR, log, null);
        }

        // Perform actual modification (or creation)
        boolean isNewKey = saveParcel.getMasterKeyId() == null;
        PgpEditKeyResult modifyResult;
        {
            PgpKeyOperation keyOperations =
                    new PgpKeyOperation(new ProgressScaler(mProgressable, 10, 60, 100), mCancelled);

            // If a key id is specified, fetch and edit
            if (!isNewKey) {
                try {

                    log.add(LogType.MSG_ED_FETCHING, 1,
                            KeyFormattingUtils.convertKeyIdToHex(saveParcel.getMasterKeyId()));
                    CanonicalizedSecretKeyRing secRing =
                            mKeyRepository.getCanonicalizedSecretKeyRing(saveParcel.getMasterKeyId());

                    modifyResult = keyOperations.modifySecretKeyRing(secRing, cryptoInput, saveParcel);
                    if (modifyResult.isPending()) {
                        log.add(modifyResult, 1);
                        return new EditKeyResult(log, modifyResult);
                    }

                } catch (NotFoundException e) {
                    log.add(LogType.MSG_ED_ERROR_KEY_NOT_FOUND, 2);
                    return new EditKeyResult(EditKeyResult.RESULT_ERROR, log, null);
                }
            } else {
                // otherwise, create new one
                modifyResult = keyOperations.createSecretKeyRing(saveParcel);
            }
        }

        // Add the result to the log
        log.add(modifyResult, 1);

        // Check if the action was cancelled
        if (checkCancelled()) {
            log.add(LogType.MSG_OPERATION_CANCELLED, 0);
            return new EditKeyResult(PgpEditKeyResult.RESULT_CANCELLED, log, null);
        }

        // If the edit operation didn't succeed, exit here
        if (!modifyResult.success()) {
            // error is already logged by modification
            return new EditKeyResult(EditKeyResult.RESULT_ERROR, log, null);
        }

        // Cannot cancel from here on out!
        mProgressable.setPreventCancel();

        // It's a success, so this must be non-null now
        UncachedKeyRing ring = modifyResult.getRing();

        if (saveParcel.isShouldUpload()) {
            byte[] keyringBytes;
            try {
                UncachedKeyRing publicKeyRing = ring.extractPublicKeyRing();
                keyringBytes = publicKeyRing.getEncoded();
            } catch (IOException e) {
                log.add(LogType.MSG_ED_ERROR_EXTRACTING_PUBLIC_UPLOAD, 1);
                return new EditKeyResult(EditKeyResult.RESULT_ERROR, log, null);
            }

            UploadKeyringParcel exportKeyringParcel =
                    UploadKeyringParcel.createWithKeyringBytes(saveParcel.getUploadKeyserver(), keyringBytes);

            UploadResult uploadResult = new UploadOperation(
                    mContext, mKeyRepository, new ProgressScaler(mProgressable, 60, 80, 100), mCancelled)
                            .execute(exportKeyringParcel, cryptoInput);

            log.add(uploadResult, 2);

            if (uploadResult.isPending()) {
                return new EditKeyResult(log, uploadResult);
            } else if (!uploadResult.success() && saveParcel.isShouldUploadAtomic()) {
                // if atomic, update fail implies edit operation should also fail and not save
                return new EditKeyResult(log, RequiredInputParcel.createRetryUploadOperation(), cryptoInput);
            }
        }

        // Save the new keyring.
        updateProgress(R.string.progress_saving, 90, 100);
        SaveKeyringResult saveResult = mKeyWritableRepository.saveSecretKeyRing(ring);
        log.add(saveResult, 1);

        if (isNewKey || saveParcel.isShouldUpload()) {
            keyMetadataDao.renewKeyLastUpdatedTime(ring.getMasterKeyId(), saveParcel.isShouldUpload());
        }

        // If the save operation didn't succeed, exit here
        if (!saveResult.success()) {
            return new EditKeyResult(EditKeyResult.RESULT_ERROR, log, null);
        }

        // A brand-new primary key that "succeeded" at creation but doesn't actually work is
        // exactly the failure mode this session already hit once (the KEM-only-master-key hang)
        // -- now generalized into a standing check instead of relying on catching each new
        // instance of the bug class individually. Only for genuinely new keys, not every edit:
        // an existing key that already passed this check on creation doesn't need re-proving
        // on every subsequent modification.
        if (isNewKey && !runPostCreationSmokeTest(ring, cryptoInput, log)) {
            return new EditKeyResult(EditKeyResult.RESULT_ERROR, log, null);
        }

        // Recorded only once a new key has actually proven itself functional (past the smoke
        // test above), not on every edit -- provenance describes generation, not modification.
        if (isNewKey) {
            keyMetadataDao.recordProvenance(ring.getMasterKeyId(), BuildConfig.VERSION_NAME, ENTROPY_SOURCE_ANDROID_SECURERANDOM);
        }

        updateProgress(R.string.progress_done, 100, 100);

        log.add(LogType.MSG_ED_SUCCESS, 0);
        return new EditKeyResult(EditKeyResult.RESULT_OK, log, ring.getMasterKeyId());

    }

    /**
     * Signs and verifies a small in-memory test message with the just-created key (every
     * primary key must be able to sign/certify -- enforced at creation time by {@link
     * SaveKeyringParcel#canCertify}), and if the key also has an encryption-capable subkey,
     * encrypts and decrypts one too. Entirely in-memory, no disk/network I/O.
     * <p>
     * This is a defense-in-depth check, not a replacement for the algorithm/flag legality
     * enforcement that already prevents the specific KEM-only-master-key case -- it exists to
     * catch some *other* class of "key created but doesn't actually work" bug before a user
     * ever finds out the hard way, the same way the KEM-only case was originally found.
     */
    private boolean runPostCreationSmokeTest(UncachedKeyRing ring, CryptoInputParcel cryptoInput, OperationLog log) {
        long masterKeyId = ring.getMasterKeyId();
        UnifiedKeyInfo keyInfo = mKeyRepository.getUnifiedKeyInfo(masterKeyId);
        if (keyInfo == null) {
            log.add(LogType.MSG_ED_ERROR_SMOKE_TEST_KEY_NOT_FOUND, 1);
            return false;
        }

        String testMessage = "OpenKeychain PQC post-creation smoke test";
        byte[] testMessageBytes = testMessage.getBytes(StandardCharsets.UTF_8);

        byte[] signedMessage;
        {
            ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
            InputData signInput = new InputData(new ByteArrayInputStream(testMessageBytes), testMessageBytes.length);

            // Deliberately not setting signatureSubKeyId: the master key itself is only
            // guaranteed to be able to certify (per SaveKeyringParcel#canCertify), not
            // necessarily to sign directly -- a certify-only master key with a separate signing
            // subkey is a normal, supported configuration. Leaving it unset makes
            // PgpSignEncryptOperation resolve the actual signing-capable subkey itself (via
            // KeyRepository#getSecretSignId), the same fallback path it already uses for every
            // other real caller that doesn't pin an explicit subkey.
            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
            pgpData.setSignatureMasterKeyId(masterKeyId);
            pgpData.setCleartextSignature(false);
            pgpData.setDetachedSignature(false);

            PgpSignEncryptOperation signOp = new PgpSignEncryptOperation(mContext, mKeyWritableRepository, null);
            PgpSignEncryptResult signResult = signOp.execute(pgpData.build(), cryptoInput, signInput, signedOut);
            if (!signResult.success()) {
                log.add(LogType.MSG_ED_ERROR_SMOKE_TEST_SIGN, 1);
                return false;
            }
            signedMessage = signedOut.toByteArray();
        }

        try {
            ByteArrayOutputStream verifiedOut = new ByteArrayOutputStream();
            InputData verifyInput = new InputData(new ByteArrayInputStream(signedMessage), signedMessage.length);

            PgpDecryptVerifyOperation verifyOp = new PgpDecryptVerifyOperation(mContext, mKeyWritableRepository, null);
            PgpDecryptVerifyInputParcel verifyInputParcel = PgpDecryptVerifyInputParcel.builder().build();
            DecryptVerifyResult verifyResult =
                    verifyOp.execute(verifyInputParcel, cryptoInput, verifyInput, verifiedOut);

            boolean signatureConfirmed = verifyResult.success()
                    && verifyResult.getSignatureResult() != null
                    && verifyResult.getSignatureResult().getResult() == OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED;
            if (!signatureConfirmed || !testMessage.equals(verifiedOut.toString("UTF-8"))) {
                log.add(LogType.MSG_ED_ERROR_SMOKE_TEST_VERIFY, 1);
                return false;
            }
        } catch (IOException e) {
            log.add(LogType.MSG_ED_ERROR_SMOKE_TEST_VERIFY, 1);
            return false;
        }

        if (!keyInfo.has_encrypt_key()) {
            return true;
        }

        byte[] encryptedMessage;
        {
            ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
            InputData encryptInput = new InputData(new ByteArrayInputStream(testMessageBytes), testMessageBytes.length);

            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
            pgpData.setEncryptionMasterKeyIds(new long[]{masterKeyId});

            PgpSignEncryptOperation encryptOp = new PgpSignEncryptOperation(mContext, mKeyWritableRepository, null);
            PgpSignEncryptResult encryptResult = encryptOp.execute(pgpData.build(), cryptoInput, encryptInput, encryptedOut);
            if (!encryptResult.success()) {
                log.add(LogType.MSG_ED_ERROR_SMOKE_TEST_ENCRYPT, 1);
                return false;
            }
            encryptedMessage = encryptedOut.toByteArray();
        }

        try {
            ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
            InputData decryptInput = new InputData(new ByteArrayInputStream(encryptedMessage), encryptedMessage.length);

            PgpDecryptVerifyOperation decryptOp = new PgpDecryptVerifyOperation(mContext, mKeyWritableRepository, null);
            PgpDecryptVerifyInputParcel decryptInputParcel = PgpDecryptVerifyInputParcel.builder().build();
            DecryptVerifyResult decryptResult =
                    decryptOp.execute(decryptInputParcel, cryptoInput, decryptInput, decryptedOut);

            if (!decryptResult.success() || !testMessage.equals(decryptedOut.toString("UTF-8"))) {
                log.add(LogType.MSG_ED_ERROR_SMOKE_TEST_DECRYPT, 1);
                return false;
            }
        } catch (IOException e) {
            log.add(LogType.MSG_ED_ERROR_SMOKE_TEST_DECRYPT, 1);
            return false;
        }

        return true;
    }
}
