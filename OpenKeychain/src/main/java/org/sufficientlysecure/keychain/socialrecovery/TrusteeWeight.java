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

import android.os.Parcelable;

import com.google.auto.value.AutoValue;

/**
 * One trustee's label and weight, as configured during setup -- the input to
 * {@link WeightedShareSplitter#split}, before any shares exist.
 */
@AutoValue
public abstract class TrusteeWeight implements Parcelable {
    public abstract String getLabel();
    public abstract int getWeight();

    public static TrusteeWeight create(String label, int weight) {
        if (label == null || label.isEmpty()) {
            throw new IllegalArgumentException("label must be non-empty");
        }
        if (weight <= 0) {
            throw new IllegalArgumentException("weight must be positive, was " + weight);
        }
        return new AutoValue_TrusteeWeight(label, weight);
    }
}
