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

/**
 * Thrown when the sum of trustee weights (the total share count {@code n} passed to
 * {@code ShamirSecretSplitter.resplit}) would exceed the byte length of the secret being split.
 *
 * This bound was empirically determined, not assumed: BouncyCastle 1.84's
 * {@code ShamirSecretSplitter} in {@code Mode.Table} caps out at exactly {@code n == secret.length}
 * -- one share past that throws an unchecked {@code ArrayIndexOutOfBoundsException} inside
 * {@code resplit()}, not the 255-share GF(2^8) ceiling a first-principles reading of "one byte
 * per field element" would suggest. For the Numeric9x4 passphrase this feature splits (36 digits
 * + 8 separators = 44 bytes), the real ceiling is 44, not 255. This exception exists so the
 * setup UI can reject an over-weighted trustee list with a clean message instead of crashing.
 */
public class TotalWeightExceedsCapacityException extends Exception {
    public final int requestedTotalWeight;
    public final int maxTotalWeight;

    public TotalWeightExceedsCapacityException(int requestedTotalWeight, int maxTotalWeight) {
        super("Total trustee weight " + requestedTotalWeight + " exceeds the maximum supported weight "
                + maxTotalWeight + " (the byte length of the secret being split)");
        this.requestedTotalWeight = requestedTotalWeight;
        this.maxTotalWeight = maxTotalWeight;
    }
}
