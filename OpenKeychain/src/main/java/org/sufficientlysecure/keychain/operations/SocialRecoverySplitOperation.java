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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;
import android.net.Uri;

import androidx.annotation.NonNull;

import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.SocialRecoveryShareDao;
import org.sufficientlysecure.keychain.operations.results.ExportResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.SocialRecoverySplitResult;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.provider.TemporaryFileProvider;
import org.sufficientlysecure.keychain.service.BackupKeyringParcel;
import org.sufficientlysecure.keychain.service.SocialRecoverySplitParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.socialrecovery.TotalWeightExceedsCapacityException;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeWeight;
import org.sufficientlysecure.keychain.socialrecovery.WeightedShareSplitter;
import org.sufficientlysecure.keychain.util.Numeric9x4PassphraseUtil;
import org.sufficientlysecure.keychain.util.Passphrase;

/**
 * Composes the existing, unmodified {@link BackupOperation} pipeline with
 * {@link WeightedShareSplitter}: generates a fresh backup passphrase, uses it to produce a real
 * encrypted {@code .sec.asc} export (the same code path and format as an ordinary backup), then
 * splits <em>that passphrase</em> -- never raw key material -- across the configured trustees.
 * Every actual OpenPGP operation here (encrypt, the eventual decrypt on restore, MDC/AEAD
 * integrity) is code this project already has independent test coverage for; this class only
 * adds the passphrase-splitting step around it.
 */
public class SocialRecoverySplitOperation extends BaseOperation<SocialRecoverySplitParcel> {
    private final SocialRecoveryShareDao socialRecoveryShareDao;

    public SocialRecoverySplitOperation(Context context, KeyRepository keyRepository,
            Progressable progressable, AtomicBoolean cancelled) {
        super(context, keyRepository, progressable, cancelled);
        this.socialRecoveryShareDao = SocialRecoveryShareDao.create(context);
    }

    @NonNull
    @Override
    public SocialRecoverySplitResult execute(SocialRecoverySplitParcel input, CryptoInputParcel cryptoInput) {
        OperationLog log = new OperationLog();
        long masterKeyId = input.getMasterKeyId();

        Passphrase backupPassphrase = Numeric9x4PassphraseUtil.generateNumeric9x4Passphrase();

        String filename = "social-recovery-" + masterKeyId + Constants.FILE_EXTENSION_ENCRYPTED_BACKUP_SECRET;
        Uri outputUri = TemporaryFileProvider.createFile(mContext, filename, Constants.MIME_TYPE_ENCRYPTED_ALTERNATE);
        BackupKeyringParcel backupParcel = BackupKeyringParcel.create(
                new long[] { masterKeyId }, true, true, true, outputUri);

        BackupOperation backupOperation = new BackupOperation(mContext, mKeyRepository, mProgressable, mCancelled);
        ExportResult backupResult = backupOperation.execute(
                backupParcel, CryptoInputParcel.createCryptoInputParcel(backupPassphrase));
        log.add(backupResult, 1);
        if (!backupResult.success()) {
            log.add(LogType.MSG_SR_ERROR_BACKUP_FAILED, 1);
            return new SocialRecoverySplitResult(SocialRecoverySplitResult.RESULT_ERROR, log, null, null, null);
        }

        byte[] secretBytes = utf8BytesOf(backupPassphrase.getCharArray());
        String ceremonyId = UUID.randomUUID().toString();
        List<TrusteeShareBundle> bundles;
        try {
            bundles = WeightedShareSplitter.split(secretBytes, input.getTrustees(), input.getThresholdWeight(),
                    masterKeyId, ceremonyId, new SecureRandom());
        } catch (TotalWeightExceedsCapacityException e) {
            log.add(LogType.MSG_SR_ERROR_TOTAL_WEIGHT_EXCEEDS_CAPACITY, 1);
            return new SocialRecoverySplitResult(SocialRecoverySplitResult.RESULT_ERROR, log, null, null, null);
        } finally {
            Arrays.fill(secretBytes, (byte) 0);
        }

        int totalWeight = 0;
        for (TrusteeWeight trustee : input.getTrustees()) {
            totalWeight += trustee.getWeight();
        }
        socialRecoveryShareDao.recordSplitCeremony(
                masterKeyId, ceremonyId, bundles, input.getThresholdWeight(), totalWeight, new Date());

        log.add(LogType.MSG_SR_SPLIT_SUCCESS, 0);
        return new SocialRecoverySplitResult(SocialRecoverySplitResult.RESULT_OK, log, ceremonyId, bundles, outputUri);
    }

    private static byte[] utf8BytesOf(char[] chars) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        if (encoded.hasArray()) {
            Arrays.fill(encoded.array(), (byte) 0);
        }
        return bytes;
    }
}
