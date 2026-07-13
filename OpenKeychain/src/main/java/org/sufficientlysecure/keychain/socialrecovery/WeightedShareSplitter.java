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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.threshold.ShamirSecretSplitter;
import org.bouncycastle.crypto.threshold.ShamirSecretSplitter.Algorithm;
import org.bouncycastle.crypto.threshold.ShamirSecretSplitter.Mode;
import org.bouncycastle.crypto.threshold.ShamirSplitSecret;
import org.bouncycastle.crypto.threshold.ShamirSplitSecretShare;

/**
 * Splits a secret (in this app, always a backup passphrase -- see the class doc of the
 * operations that call this) into weighted per-trustee share bundles, on top of BouncyCastle
 * 1.84's {@code ShamirSecretSplitter}.
 * <p>
 * Two things here were empirically determined against the actual jar on this project's
 * classpath, not assumed from BC's public docs or an earlier design pass:
 * <ol>
 * <li>{@code resplit(secret, m, n)} caps out at exactly {@code n == secret.length} -- one share
 * past that throws an unchecked {@link ArrayIndexOutOfBoundsException} inside {@code resplit()}
 * itself. This is <em>not</em> the 255-share GF(2^8) ceiling a "one byte per field element"
 * reading would suggest. See {@link TotalWeightExceedsCapacityException}, which turns that crash
 * into a clean, catchable error before BC is ever called.</li>
 * <li>{@code ShamirSplitSecretShare} exposes no public getter for its own {@code r} index --
 * only package-private field access. But shares come back from {@code getSecretShares()} in
 * strict sequential r-order (share at array index {@code i} has {@code r == i + 1}), so this
 * class tracks r-index itself by array position rather than needing to read it back from BC.
 * Verified by round-tripping shares through {@code getEncoded()} + a hand-tracked r into the
 * public {@code ShamirSplitSecretShare(byte[], int)} constructor and confirming reconstruction
 * still succeeds (including with shares presented out of order).</li>
 * </ol>
 */
public class WeightedShareSplitter {

    private WeightedShareSplitter() {
    }

    public static List<TrusteeShareBundle> split(byte[] secretBytes, List<TrusteeWeight> trustees,
            int thresholdWeight, long masterKeyId, String ceremonyId, SecureRandom random)
            throws TotalWeightExceedsCapacityException {
        if (secretBytes == null || secretBytes.length == 0) {
            throw new IllegalArgumentException("secretBytes must not be empty");
        }
        if (trustees == null || trustees.isEmpty()) {
            throw new IllegalArgumentException("must have at least one trustee");
        }

        int totalWeight = 0;
        for (TrusteeWeight trustee : trustees) {
            totalWeight += trustee.getWeight();
        }
        if (totalWeight > secretBytes.length) {
            throw new TotalWeightExceedsCapacityException(totalWeight, secretBytes.length);
        }
        if (thresholdWeight <= 0 || thresholdWeight > totalWeight) {
            throw new IllegalArgumentException("thresholdWeight must be positive and at most the total "
                    + "trustee weight (" + totalWeight + "), was " + thresholdWeight);
        }

        ShamirSecretSplitter splitter = new ShamirSecretSplitter(Algorithm.AES, Mode.Table, secretBytes.length, random);
        ShamirSplitSecret split = splitter.resplit(secretBytes, thresholdWeight, totalWeight);
        ShamirSplitSecretShare[] allShares = split.getSecretShares();

        List<TrusteeShareBundle> bundles = new ArrayList<>(trustees.size());
        int cursor = 0;
        for (TrusteeWeight trustee : trustees) {
            List<Integer> indices = new ArrayList<>(trustee.getWeight());
            List<byte[]> shareBytes = new ArrayList<>(trustee.getWeight());
            for (int i = 0; i < trustee.getWeight(); i++) {
                int rIndex = cursor + 1;
                indices.add(rIndex);
                shareBytes.add(encode(allShares[cursor]));
                cursor++;
            }
            bundles.add(TrusteeShareBundle.create(trustee.getLabel(), indices, shareBytes, masterKeyId, ceremonyId,
                    thresholdWeight, totalWeight));
        }
        return bundles;
    }

    private static byte[] encode(ShamirSplitSecretShare share) {
        try {
            return share.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("encoding a freshly-produced share must not fail", e);
        }
    }
}
