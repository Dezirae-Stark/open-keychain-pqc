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
 * Thrown when a contributed {@link TrusteeShareBundle} carries a masterKeyId/ceremonyId that
 * doesn't match the recovery attempt currently in progress -- catches a share that was
 * genuinely produced by a different (independent) split ceremony, before it ever reaches GF
 * arithmetic. This is a binder check, not a cryptographic authentication of the share itself
 * (see the class doc of {@link WeightedShareReconstructor} for how tampered shares are caught).
 */
public class ShareBindingMismatchException extends Exception {
    public final long expectedMasterKeyId;
    public final long actualMasterKeyId;
    public final String expectedCeremonyId;
    public final String actualCeremonyId;

    public ShareBindingMismatchException(long expectedMasterKeyId, long actualMasterKeyId,
            String expectedCeremonyId, String actualCeremonyId) {
        super("Share binding mismatch: expected masterKeyId=" + expectedMasterKeyId + " ceremonyId="
                + expectedCeremonyId + ", got masterKeyId=" + actualMasterKeyId + " ceremonyId=" + actualCeremonyId);
        this.expectedMasterKeyId = expectedMasterKeyId;
        this.actualMasterKeyId = actualMasterKeyId;
        this.expectedCeremonyId = expectedCeremonyId;
        this.actualCeremonyId = actualCeremonyId;
    }
}
