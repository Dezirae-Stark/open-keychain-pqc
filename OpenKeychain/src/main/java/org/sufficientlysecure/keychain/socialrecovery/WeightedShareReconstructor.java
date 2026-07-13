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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.threshold.ShamirSecretSplitter.Algorithm;
import org.bouncycastle.crypto.threshold.ShamirSecretSplitter.Mode;
import org.bouncycastle.crypto.threshold.ShamirSplitSecret;
import org.bouncycastle.crypto.threshold.ShamirSplitSecretShare;

/**
 * Reconstructs a secret from a set of contributed {@link TrusteeShareBundle}s. Does not itself
 * verify the reconstructed bytes are correct -- a tampered or wrong share doesn't throw here (it
 * silently produces different bytes; confirmed empirically -- wrong r/share pairing changes the
 * Lagrange interpolation result, it doesn't crash or coincidentally match). Tamper detection is
 * the caller's job: attempt the real decrypt this passphrase is meant to unlock, and only report
 * recovery success if that decrypt actually succeeds. That's free -- the pipeline needs to run
 * this decrypt anyway to actually produce the recovered key.
 */
public class WeightedShareReconstructor {

    private WeightedShareReconstructor() {
    }

    public static byte[] reconstruct(List<TrusteeShareBundle> contributedBundles, int thresholdWeight,
            long expectedMasterKeyId, String expectedCeremonyId)
            throws InsufficientWeightException, ShareBindingMismatchException, IOException {
        if (contributedBundles == null || contributedBundles.isEmpty()) {
            throw new InsufficientWeightException(0, thresholdWeight);
        }

        for (TrusteeShareBundle bundle : contributedBundles) {
            if (bundle.getMasterKeyId() != expectedMasterKeyId
                    || !bundle.getCeremonyId().equals(expectedCeremonyId)) {
                throw new ShareBindingMismatchException(expectedMasterKeyId, bundle.getMasterKeyId(),
                        expectedCeremonyId, bundle.getCeremonyId());
            }
        }

        // Dedupe by r-index: defends against one trustee resubmitting their own share(s) to
        // fake extra weight. LinkedHashMap so the first-seen bytes for a given index win and
        // iteration order stays deterministic.
        Map<Integer, byte[]> sharesByIndex = new LinkedHashMap<>();
        for (TrusteeShareBundle bundle : contributedBundles) {
            List<Integer> indices = bundle.getShareIndices();
            List<byte[]> shareBytes = bundle.getShareBytes();
            for (int i = 0; i < indices.size(); i++) {
                sharesByIndex.putIfAbsent(indices.get(i), shareBytes.get(i));
            }
        }

        // Weight is the deduped *distinct r-index* count, not raw contributed share count --
        // this is what catches "3 trustees hand over 3 shares but required weight is 4" (a
        // trustee's shares only count once each, but the check is on distinct indices, not on
        // trustee count or bundle count).
        int contributedWeight = sharesByIndex.size();
        if (contributedWeight < thresholdWeight) {
            throw new InsufficientWeightException(contributedWeight, thresholdWeight);
        }

        // Truncate to exactly thresholdWeight shares before calling getSecret(). Empirically,
        // this BC version reconstructs correctly from a superset too (see WeightedShareSplitter's
        // class doc) -- truncation here is for determinism/predictability, not because a superset
        // is known to corrupt the result.
        List<Integer> sortedIndices = new ArrayList<>(sharesByIndex.keySet());
        Collections.sort(sortedIndices);
        List<Integer> truncatedIndices = sortedIndices.subList(0, thresholdWeight);

        ShamirSplitSecretShare[] sharesForReconstruction = new ShamirSplitSecretShare[thresholdWeight];
        for (int i = 0; i < thresholdWeight; i++) {
            int rIndex = truncatedIndices.get(i);
            sharesForReconstruction[i] = new ShamirSplitSecretShare(sharesByIndex.get(rIndex), rIndex);
        }

        ShamirSplitSecret splitSecret = new ShamirSplitSecret(Algorithm.AES, Mode.Table, sharesForReconstruction);
        return splitSecret.getSecret();
    }
}
