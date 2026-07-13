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
 * Thrown when the summed weight of contributed trustee shares falls short of the recovery
 * threshold -- checked and rejected before any GF(2^8) arithmetic runs, so a quorum failure
 * is a clean, explicit error rather than a wrong-bytes/decrypt-failure surprise downstream.
 */
public class InsufficientWeightException extends Exception {
    public final int contributedWeight;
    public final int requiredWeight;

    public InsufficientWeightException(int contributedWeight, int requiredWeight) {
        super("Insufficient trustee weight: contributed " + contributedWeight
                + ", required " + requiredWeight);
        this.contributedWeight = contributedWeight;
        this.requiredWeight = requiredWeight;
    }
}
