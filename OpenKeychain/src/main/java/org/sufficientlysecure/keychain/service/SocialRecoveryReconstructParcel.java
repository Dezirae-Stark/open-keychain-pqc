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

package org.sufficientlysecure.keychain.service;

import java.util.List;

import android.os.Parcelable;

import com.google.auto.value.AutoValue;

import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;

/**
 * Input to {@code SocialRecoveryReconstructOperation}: the collected trustee share bundles for
 * one recovery attempt, plus the backup artifact (as bytes -- the caller reads it from wherever
 * it was stored/imported) that the reconstructed passphrase is meant to unlock.
 */
@AutoValue
public abstract class SocialRecoveryReconstructParcel implements Parcelable {
    public abstract long getMasterKeyId();
    public abstract String getCeremonyId();
    public abstract List<TrusteeShareBundle> getContributedBundles();
    public abstract byte[] getEncryptedBackupBytes();

    public static SocialRecoveryReconstructParcel create(long masterKeyId, String ceremonyId,
            List<TrusteeShareBundle> contributedBundles, byte[] encryptedBackupBytes) {
        return new AutoValue_SocialRecoveryReconstructParcel(
                masterKeyId, ceremonyId, contributedBundles, encryptedBackupBytes);
    }
}
