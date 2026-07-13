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

import java.util.Arrays;

import android.os.Parcel;

import androidx.lifecycle.SavedStateHandle;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.R;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(KeychainTestRunner.class)
public class CeremonyViewModelTest {

    private static final CeremonyStepSpec STEP_1 =
            CeremonyStepSpec.create("step1", R.string.app_name, R.string.app_name);
    private static final CeremonyStepSpec STEP_2 =
            CeremonyStepSpec.create("step2", R.string.app_name, R.string.app_name);
    private static final CeremonyStepSpec STEP_3_TYPED = CeremonyStepSpec.createWithTypedConfirmation(
            "step3", R.string.app_name, R.string.app_name, "REVOKE");

    private CeremonySpec threeStepSpec;
    private CeremonyViewModel viewModel;

    @Before
    public void setUp() {
        threeStepSpec = CeremonySpec.create("test_ceremony", Arrays.asList(STEP_1, STEP_2, STEP_3_TYPED));
        viewModel = new CeremonyViewModel(new SavedStateHandle());
        viewModel.initIfNeeded(threeStepSpec);
    }

    @Test
    public void initIfNeeded_startsAtStepZeroWithNothingAcknowledged() {
        CeremonyState state = viewModel.getState().getValue();
        assertEquals(0, state.getCurrentStepIndex());
        assertFalse(state.isComplete());
        for (CeremonyStepState stepState : state.getStepStates()) {
            assertFalse(stepState.getIsAcknowledged());
        }
    }

    @Test
    public void initIfNeeded_calledTwice_doesNotResetProgress() {
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.initIfNeeded(threeStepSpec); // simulates a resumed process

        assertTrue(viewModel.canAdvance());
    }

    @Test
    public void canAdvance_falseUntilCurrentStepAcknowledged() {
        assertFalse(viewModel.canAdvance());
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        assertTrue(viewModel.canAdvance());
    }

    @Test
    public void goToNextStep_withoutAcknowledgment_isANoOp() {
        viewModel.goToNextStep(threeStepSpec);
        assertEquals(0, viewModel.getState().getValue().getCurrentStepIndex());
    }

    @Test
    public void goToNextStep_afterAcknowledgment_advances() {
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);
        assertEquals(1, viewModel.getState().getValue().getCurrentStepIndex());
    }

    @Test
    public void acknowledgeCurrentStep_doesNotRetroactivelyAcknowledgeLaterSteps() {
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);

        assertFalse(viewModel.canAdvance());
        assertFalse(viewModel.isReadyToExecute());
    }

    @Test
    public void typedConfirmation_wrongTextDoesNotAcknowledge() {
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);
        // now on step3, which requires typing "REVOKE"

        viewModel.acknowledgeCurrentStep(threeStepSpec, "revoke"); // wrong case
        assertFalse(viewModel.canAdvance());

        viewModel.acknowledgeCurrentStep(threeStepSpec, "REVOK"); // wrong text
        assertFalse(viewModel.canAdvance());

        viewModel.acknowledgeCurrentStep(threeStepSpec, null); // nothing typed
        assertFalse(viewModel.canAdvance());
    }

    @Test
    public void typedConfirmation_exactTextAcknowledges() {
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);

        viewModel.acknowledgeCurrentStep(threeStepSpec, "REVOKE");
        assertTrue(viewModel.canAdvance());
    }

    @Test
    public void isReadyToExecute_falseUntilEveryStepAcknowledged() {
        assertFalse(viewModel.isReadyToExecute());

        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);
        assertFalse(viewModel.isReadyToExecute());

        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);
        assertFalse(viewModel.isReadyToExecute());

        viewModel.acknowledgeCurrentStep(threeStepSpec, "REVOKE");
        assertTrue(viewModel.isReadyToExecute());
    }

    @Test
    public void isReadyToExecute_reDerivesFromStepStatesNotJustCurrentIndex() {
        // Simulate a bug/manipulation that forces currentStepIndex to the last step without
        // ever acknowledging the earlier ones -- isReadyToExecute must still say false, since
        // it re-checks every step's own acknowledgment, not "did we reach the end."
        CeremonyState manipulated = viewModel.getState().getValue().withCurrentStepIndex(2);
        SavedStateHandle handle = new SavedStateHandle();
        handle.set("ceremony_state", manipulated);
        CeremonyViewModel manipulatedViewModel = new CeremonyViewModel(handle);

        assertFalse(manipulatedViewModel.isReadyToExecute());
    }

    @Test
    public void goToPreviousStep_movesBackAndClampsAtZero() {
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        viewModel.goToNextStep(threeStepSpec);
        assertEquals(1, viewModel.getState().getValue().getCurrentStepIndex());

        viewModel.goToPreviousStep();
        assertEquals(0, viewModel.getState().getValue().getCurrentStepIndex());

        viewModel.goToPreviousStep(); // already at 0
        assertEquals(0, viewModel.getState().getValue().getCurrentStepIndex());
    }

    @Test
    public void ceremonyState_parcelRoundTrip() {
        viewModel.acknowledgeCurrentStep(threeStepSpec, null);
        CeremonyState original = viewModel.getState().getValue();

        Parcel parcel = Parcel.obtain();
        parcel.writeParcelable(original, 0);
        parcel.setDataPosition(0);
        CeremonyState restored = parcel.readParcelable(CeremonyState.class.getClassLoader());
        parcel.recycle();

        assertEquals(original.getCeremonyId(), restored.getCeremonyId());
        assertEquals(original.getCurrentStepIndex(), restored.getCurrentStepIndex());
        assertEquals(original.getStepStates().size(), restored.getStepStates().size());
        for (int i = 0; i < original.getStepStates().size(); i++) {
            assertEquals(original.getStepStates().get(i).getStepId(), restored.getStepStates().get(i).getStepId());
            assertEquals(original.getStepStates().get(i).getIsAcknowledged(), restored.getStepStates().get(i).getIsAcknowledged());
        }
    }
}
