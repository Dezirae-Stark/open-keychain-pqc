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

package org.sufficientlysecure.keychain.socialrecovery;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import android.os.Parcelable;

import com.google.auto.value.AutoValue;

/**
 * One trustee's allotment of raw Shamir shares -- a weight-N trustee holds N raw shares (one
 * per r-index), bundled together with the binder (masterKeyId + ceremonyId) that ties them to a
 * specific split ceremony, and a verification-only checksum. This is metadata this feature owns
 * entirely; {@code ShamirSplitSecretShare} itself exposes no way to read back its own r-index
 * (see {@link WeightedShareSplitter}'s class doc), so r-index bookkeeping happens here.
 */
@AutoValue
public abstract class TrusteeShareBundle implements Parcelable {
    public abstract String getTrusteeLabel();
    public abstract int getWeight();
    public abstract List<Integer> getShareIndices();
    public abstract List<byte[]> getShareBytes();
    public abstract long getMasterKeyId();
    public abstract String getCeremonyId();
    public abstract String getShareChecksum();
    // Purely informational, not used in reconstruction math -- embedded so a SINGLE received
    // share is self-describing enough to know "how much total weight is needed." Recovery
    // typically happens on a device that never had the original device's local ceremony
    // metadata (SocialRecoveryShareDao's rows), so the threshold can't be looked up locally
    // during restore; it has to travel with the shares themselves.
    public abstract int getThresholdWeight();
    public abstract int getTotalWeight();

    public static TrusteeShareBundle create(String trusteeLabel, List<Integer> shareIndices,
            List<byte[]> shareBytes, long masterKeyId, String ceremonyId, int thresholdWeight, int totalWeight) {
        if (shareIndices.size() != shareBytes.size()) {
            throw new IllegalArgumentException("shareIndices and shareBytes must be the same length");
        }
        if (shareIndices.isEmpty()) {
            throw new IllegalArgumentException("a trustee bundle must carry at least one share");
        }
        String checksum = computeChecksum(shareBytes);
        return new AutoValue_TrusteeShareBundle(trusteeLabel, shareIndices.size(), shareIndices, shareBytes,
                masterKeyId, ceremonyId, checksum, thresholdWeight, totalWeight);
    }

    public boolean matchesChecksum() {
        return getShareChecksum().equals(computeChecksum(getShareBytes()));
    }

    private static String computeChecksum(List<byte[]> shareBytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] share : shareBytes) {
                digest.update(share);
            }
            byte[] hash = digest.digest();
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must always be available", e);
        }
    }
}
