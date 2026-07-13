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

package org.sufficientlysecure.keychain.operations.results;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import android.net.Uri;
import android.os.Parcel;

import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;

/**
 * Carries the produced per-trustee share bundles back to the setup UI so it can display/export
 * them for out-of-band distribution -- these bundles are the only place the raw shares exist in
 * this operation's output; nothing else in this result (or persisted by the operation) contains
 * share material.
 */
public class SocialRecoverySplitResult extends OperationResult {

    public final String ceremonyId;
    public final List<TrusteeShareBundle> trusteeBundles;
    public final Uri encryptedBackupUri;

    public SocialRecoverySplitResult(int result, OperationLog log, String ceremonyId,
            List<TrusteeShareBundle> trusteeBundles, Uri encryptedBackupUri) {
        super(result, log);
        this.ceremonyId = ceremonyId;
        this.trusteeBundles = trusteeBundles != null ? trusteeBundles : Collections.emptyList();
        this.encryptedBackupUri = encryptedBackupUri;
    }

    @SuppressWarnings("unchecked")
    public SocialRecoverySplitResult(Parcel source) {
        super(source);
        ceremonyId = source.readString();
        // TrusteeShareBundle's CREATOR lives on the AutoValue-generated subclass, not on this
        // abstract type, so a typed list read (which needs a fixed CREATOR reference) isn't
        // available here -- readArrayList resolves each element's concrete class dynamically,
        // the same pattern used for other AutoValue Parcelables in this codebase.
        List<TrusteeShareBundle> bundles =
                source.readArrayList(TrusteeShareBundle.class.getClassLoader());
        trusteeBundles = bundles != null ? bundles : new ArrayList<>();
        encryptedBackupUri = source.readParcelable(Uri.class.getClassLoader());
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        super.writeToParcel(dest, flags);
        dest.writeString(ceremonyId);
        dest.writeList(trusteeBundles);
        dest.writeParcelable(encryptedBackupUri, flags);
    }

    public static final Creator<SocialRecoverySplitResult> CREATOR = new Creator<SocialRecoverySplitResult>() {
        public SocialRecoverySplitResult createFromParcel(final Parcel source) {
            return new SocialRecoverySplitResult(source);
        }

        public SocialRecoverySplitResult[] newArray(final int size) {
            return new SocialRecoverySplitResult[size];
        }
    };
}
