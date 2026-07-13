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

import android.os.Parcel;

public class SocialRecoveryReconstructResult extends OperationResult {

    public final Long recoveredMasterKeyId;

    public SocialRecoveryReconstructResult(int result, OperationLog log, Long recoveredMasterKeyId) {
        super(result, log);
        this.recoveredMasterKeyId = recoveredMasterKeyId;
    }

    public SocialRecoveryReconstructResult(Parcel source) {
        super(source);
        recoveredMasterKeyId = source.readInt() != 0 ? source.readLong() : null;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        super.writeToParcel(dest, flags);
        if (recoveredMasterKeyId != null) {
            dest.writeInt(1);
            dest.writeLong(recoveredMasterKeyId);
        } else {
            dest.writeInt(0);
        }
    }

    public static final Creator<SocialRecoveryReconstructResult> CREATOR =
            new Creator<SocialRecoveryReconstructResult>() {
        public SocialRecoveryReconstructResult createFromParcel(final Parcel source) {
            return new SocialRecoveryReconstructResult(source);
        }

        public SocialRecoveryReconstructResult[] newArray(final int size) {
            return new SocialRecoveryReconstructResult[size];
        }
    };
}
