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

import java.util.ArrayList;
import java.util.List;

import android.os.Parcelable;

import com.google.auto.value.AutoValue;

/**
 * The entire state of one in-progress ceremony: one typed, Parcelable object, replacing the
 * pattern of raw public mutable fields on the hosting Activity that {@code CreateKeyActivity}
 * uses for its own (unrelated, untouched by this class) multi-step flow. {@link
 * androidx.lifecycle.SavedStateHandle} persists this directly across process death, so no
 * hand-written {@code onSaveInstanceState}/restore boilerplate is needed per field the way
 * {@code CreateKeyActivity} needs it today.
 * <p>
 * {@link #isComplete} is the actual security property this whole package exists to provide: it
 * re-checks every step fresh, not just {@code currentStepIndex} bookkeeping, so a bug in index
 * management (or a manipulated back stack) can't produce a false "ceremony complete" signal --
 * see {@code CeremonyViewModel#isReadyToExecute}, the only method that's allowed to say a
 * ceremony is done.
 */
@AutoValue
public abstract class CeremonyState implements Parcelable {
    public abstract String getCeremonyId();
    public abstract List<CeremonyStepState> getStepStates();
    public abstract int getCurrentStepIndex();

    public static CeremonyState initial(String ceremonyId, List<CeremonyStepState> stepStates) {
        return new AutoValue_CeremonyState(ceremonyId, stepStates, 0);
    }

    public CeremonyState withCurrentStepIndex(int index) {
        return new AutoValue_CeremonyState(getCeremonyId(), getStepStates(), index);
    }

    public CeremonyState withStepAcknowledged(int index, String typedConfirmationText) {
        List<CeremonyStepState> newStates = new ArrayList<>(getStepStates());
        newStates.set(index, newStates.get(index).withAcknowledged(typedConfirmationText));
        return new AutoValue_CeremonyState(getCeremonyId(), newStates, getCurrentStepIndex());
    }

    /** True only once every step, not just the current one, is acknowledged. */
    public boolean isComplete() {
        for (CeremonyStepState state : getStepStates()) {
            if (!state.getIsAcknowledged()) {
                return false;
            }
        }
        return true;
    }
}
