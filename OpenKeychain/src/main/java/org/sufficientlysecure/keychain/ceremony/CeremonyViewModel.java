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

import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.SavedStateHandle;
import androidx.lifecycle.ViewModel;

/**
 * The ceremony state machine. {@code CeremonyActivity} is a thin, generic renderer of whatever
 * this class says the current state is -- all step-advancement and no-skip enforcement logic
 * lives here, not in the Activity, so it's unit-testable without a Robolectric Activity/View
 * setup (see {@code CeremonyViewModelTest}).
 * <p>
 * No-skip enforcement is deliberately two layers deep: {@link #canAdvance} is what the UI's
 * "Continue" button enablement reads (so a user literally cannot tap past an unacknowledged
 * step), and {@link #isReadyToExecute} is what {@code CeremonyActivity} checks before returning
 * {@code RESULT_OK} (so even a bug in the UI layer's index bookkeeping can't produce a false
 * "ceremony complete" result -- it re-derives completeness from {@link CeremonyState#isComplete}
 * fresh, not from having merely reached the last step).
 */
public class CeremonyViewModel extends ViewModel {
    private static final String KEY_STATE = "ceremony_state";

    private final SavedStateHandle savedStateHandle;

    public CeremonyViewModel(SavedStateHandle savedStateHandle) {
        this.savedStateHandle = savedStateHandle;
    }

    /** No-op if state already exists -- the resumed-after-process-death case. */
    public void initIfNeeded(CeremonySpec spec) {
        if (savedStateHandle.get(KEY_STATE) != null) {
            return;
        }
        List<CeremonyStepState> initialStates = new ArrayList<>();
        for (CeremonyStepSpec step : spec.getSteps()) {
            initialStates.add(CeremonyStepState.initial(step.getStepId()));
        }
        savedStateHandle.set(KEY_STATE, CeremonyState.initial(spec.getCeremonyKind(), initialStates));
    }

    public LiveData<CeremonyState> getState() {
        return savedStateHandle.getLiveData(KEY_STATE);
    }

    @Nullable
    private CeremonyState getStateOrNull() {
        return savedStateHandle.get(KEY_STATE);
    }

    /**
     * Acknowledges the current step. For a step requiring typed confirmation, this is a no-op
     * (nothing becomes acknowledged) unless {@code typedText} exactly matches the spec's
     * required text -- there is no partial credit.
     */
    public void acknowledgeCurrentStep(CeremonySpec spec, @Nullable String typedText) {
        CeremonyState state = getStateOrNull();
        if (state == null) {
            return;
        }
        int index = state.getCurrentStepIndex();
        CeremonyStepSpec currentSpec = spec.getSteps().get(index);
        if (currentSpec.getRequiresTypedConfirmation()
                && !currentSpec.getRequiredTypedText().equals(typedText)) {
            return;
        }
        savedStateHandle.set(KEY_STATE, state.withStepAcknowledged(index, typedText));
    }

    public boolean canAdvance() {
        CeremonyState state = getStateOrNull();
        if (state == null) {
            return false;
        }
        return state.getStepStates().get(state.getCurrentStepIndex()).getIsAcknowledged();
    }

    public void goToNextStep(CeremonySpec spec) {
        CeremonyState state = getStateOrNull();
        if (state == null || !canAdvance()) {
            return;
        }
        int nextIndex = Math.min(state.getCurrentStepIndex() + 1, spec.getSteps().size() - 1);
        savedStateHandle.set(KEY_STATE, state.withCurrentStepIndex(nextIndex));
    }

    public void goToPreviousStep() {
        CeremonyState state = getStateOrNull();
        if (state == null) {
            return;
        }
        int prevIndex = Math.max(state.getCurrentStepIndex() - 1, 0);
        savedStateHandle.set(KEY_STATE, state.withCurrentStepIndex(prevIndex));
    }

    public boolean isOnLastStep(CeremonySpec spec) {
        CeremonyState state = getStateOrNull();
        return state != null && state.getCurrentStepIndex() == spec.getSteps().size() - 1;
    }

    public boolean isOnFirstStep() {
        CeremonyState state = getStateOrNull();
        return state == null || state.getCurrentStepIndex() == 0;
    }

    /** The only method allowed to say a ceremony is done -- see class Javadoc. */
    public boolean isReadyToExecute() {
        CeremonyState state = getStateOrNull();
        return state != null && state.isComplete();
    }
}
