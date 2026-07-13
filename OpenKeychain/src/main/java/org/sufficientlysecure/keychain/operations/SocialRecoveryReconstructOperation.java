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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;

import androidx.annotation.NonNull;

import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.operations.results.DecryptVerifyResult;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.SocialRecoveryReconstructResult;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyInputParcel;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyOperation;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing.IteratorWithIOThrow;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.service.SocialRecoveryReconstructParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.socialrecovery.InsufficientWeightException;
import org.sufficientlysecure.keychain.socialrecovery.ShareBindingMismatchException;
import org.sufficientlysecure.keychain.socialrecovery.WeightedShareReconstructor;
import org.sufficientlysecure.keychain.util.Numeric9x4PassphraseUtil;
import org.sufficientlysecure.keychain.util.Passphrase;

/**
 * Reconstructs the backup passphrase from contributed trustee shares, then feeds it into the
 * existing, unmodified decrypt ({@link PgpDecryptVerifyOperation}) and import
 * ({@link ImportOperation}) pipeline -- the same code path an ordinary "restore from backup"
 * already uses. No new decrypt code, no raw secret key material ever touches disk in an
 * unencrypted intermediate form (the decrypted armored keyring bytes only ever exist in memory,
 * handed directly from the decrypt step to the import step).
 * <p>
 * Tamper detection is intentionally free, not a separate mechanism: a wrong or tampered share
 * reconstructs to different passphrase bytes (see {@link WeightedShareReconstructor}'s class
 * doc), which then fails to decrypt the real backup -- exactly the same failure this pipeline
 * already needs to handle for an ordinary mistyped backup passphrase.
 */
public class SocialRecoveryReconstructOperation extends BaseReadWriteOperation<SocialRecoveryReconstructParcel> {

    public SocialRecoveryReconstructOperation(Context context, KeyWritableRepository databaseInteractor,
            Progressable progressable, AtomicBoolean cancelled) {
        super(context, databaseInteractor, progressable, cancelled);
    }

    @NonNull
    @Override
    public SocialRecoveryReconstructResult execute(SocialRecoveryReconstructParcel input, CryptoInputParcel cryptoInput) {
        OperationLog log = new OperationLog();

        if (input.getContributedBundles().isEmpty()) {
            log.add(LogType.MSG_SR_ERROR_INSUFFICIENT_WEIGHT, 1);
            return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
        }
        // The threshold isn't looked up from local DB metadata -- recovery typically happens on
        // a device that never had it (see TrusteeShareBundle's class doc) -- it travels with
        // every share instead. Any bundle disagreeing with the first is itself evidence of a
        // cross-ceremony mix, which the binder check below also independently catches.
        int thresholdWeight = input.getContributedBundles().get(0).getThresholdWeight();
        for (org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle bundle : input.getContributedBundles()) {
            if (bundle.getThresholdWeight() != thresholdWeight) {
                log.add(LogType.MSG_SR_ERROR_BINDING_MISMATCH, 1);
                return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
            }
        }

        byte[] passphraseBytes;
        try {
            passphraseBytes = WeightedShareReconstructor.reconstruct(input.getContributedBundles(),
                    thresholdWeight, input.getMasterKeyId(), input.getCeremonyId());
        } catch (InsufficientWeightException e) {
            log.add(LogType.MSG_SR_ERROR_INSUFFICIENT_WEIGHT, 1);
            return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
        } catch (ShareBindingMismatchException e) {
            log.add(LogType.MSG_SR_ERROR_BINDING_MISMATCH, 1);
            return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
        } catch (IOException e) {
            log.add(LogType.MSG_SR_ERROR_DECRYPT_FAILED, 1);
            return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
        }

        Passphrase reconstructedPassphrase;
        try {
            reconstructedPassphrase = new Passphrase(new String(passphraseBytes, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(passphraseBytes, (byte) 0);
        }

        PgpDecryptVerifyInputParcel decryptInput = PgpDecryptVerifyInputParcel.builder()
                .setInputBytes(input.getEncryptedBackupBytes())
                .setAllowSymmetricDecryption(true)
                .build();
        PgpDecryptVerifyOperation decryptOperation =
                new PgpDecryptVerifyOperation(mContext, mKeyRepository, mProgressable);
        DecryptVerifyResult decryptResult = decryptOperation.execute(
                decryptInput, CryptoInputParcel.createCryptoInputParcel(reconstructedPassphrase));
        log.add(decryptResult, 1);
        if (!decryptResult.success()) {
            // A wrong/tampered share produces the wrong passphrase, which fails here -- this IS
            // the tamper-detection mechanism, not a separate check (see class doc).
            log.add(LogType.MSG_SR_ERROR_DECRYPT_FAILED, 1);
            return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
        }

        byte[] decryptedArmoredKeyring = decryptResult.getOutputBytes();
        // The decrypted backup is BackupOperation's normal output shape -- both a public-only
        // and a secret encoding of the key, one after another in the same stream (BackupOperation
        // always exports public alongside secret; there's no supported way to ask it for
        // secret-only). ImportKeyringParcel.createFromBytes assumes exactly one keyring and
        // throws on this, so each keyring is decoded and re-encoded individually here, then
        // handed to the same multi-entry ImportOperation path a normal multi-key import already
        // uses -- its own existing merge logic combines the public+secret entries for one master
        // key id, exactly as it would for an ordinary backup restore.
        List<ParcelableKeyRing> keyRings = new ArrayList<>();
        try {
            IteratorWithIOThrow<UncachedKeyRing> rings =
                    UncachedKeyRing.fromStream(new ByteArrayInputStream(decryptedArmoredKeyring));
            while (rings.hasNext()) {
                keyRings.add(ParcelableKeyRing.createFromEncodedBytes(rings.next().getEncoded()));
            }
        } catch (IOException e) {
            log.add(LogType.MSG_SR_ERROR_IMPORT_FAILED, 1);
            return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
        }
        ImportKeyringParcel importParcel = ImportKeyringParcel.createImportKeyringParcel(keyRings, null);
        ImportOperation importOperation =
                new ImportOperation(mContext, mKeyWritableRepository, mProgressable, mCancelled);
        ImportKeyResult importResult = importOperation.execute(importParcel, CryptoInputParcel.createCryptoInputParcel());
        log.add(importResult, 1);
        if (!importResult.success()) {
            log.add(LogType.MSG_SR_ERROR_IMPORT_FAILED, 1);
            return new SocialRecoveryReconstructResult(SocialRecoveryReconstructResult.RESULT_ERROR, log, null);
        }

        log.add(LogType.MSG_SR_RECONSTRUCT_SUCCESS, 0);
        return new SocialRecoveryReconstructResult(
                SocialRecoveryReconstructResult.RESULT_OK, log, input.getMasterKeyId());
    }
}
