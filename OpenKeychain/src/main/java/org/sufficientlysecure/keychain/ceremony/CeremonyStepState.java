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

package org.sufficientlysecure.keychain.ceremony;

import android.os.Parcelable;

import androidx.annotation.Nullable;

import com.google.auto.value.AutoValue;

/**
 * Per-instance acknowledgment state for one {@link CeremonyStepSpec}. Immutable-by-copy (see
 * {@link #withAcknowledged}) rather than a mutable field, so {@link CeremonyState} as a whole
 * stays a plain, comparable, Parcelable-safe value -- the same reason {@code SaveKeyringParcel}'s
 * AutoValue classes are structured this way.
 */
@AutoValue
public abstract class CeremonyStepState implements Parcelable {
    public abstract String getStepId();
    public abstract boolean getIsAcknowledged();
    @Nullable public abstract String getTypedConfirmationText();

    public static CeremonyStepState initial(String stepId) {
        return new AutoValue_CeremonyStepState(stepId, false, null);
    }

    public CeremonyStepState withAcknowledged(@Nullable String typedConfirmationText) {
        return new AutoValue_CeremonyStepState(getStepId(), true, typedConfirmationText);
    }
}
