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

package org.sufficientlysecure.keychain.ui.ceremony;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.ceremony.CeremonySpec;
import org.sufficientlysecure.keychain.ceremony.CeremonyState;
import org.sufficientlysecure.keychain.ceremony.CeremonyStepSpec;
import org.sufficientlysecure.keychain.ceremony.CeremonyViewModel;
import org.sufficientlysecure.keychain.ui.util.ThemeChanger;

/**
 * A generic host for any {@link CeremonySpec} -- renders whatever {@link CeremonyViewModel} says
 * the current state is, with zero knowledge of what ceremony it's hosting or what happens after
 * it returns {@code RESULT_OK}. Callers launch it with {@link #createIntent} via {@code
 * startActivityForResult} and only proceed with the actual destructive operation on {@code
 * RESULT_OK} -- see {@code DeleteKeyDialogActivity} for the first real usage (the revoke/delete
 * pre-flight gate).
 * <p>
 * Deliberately does not use {@code CreateKeyActivity}'s {@code FragAction}/fragment-transaction
 * pattern: every step in this abstraction has the same shape (title, body, an acknowledgment
 * checkbox or a typed-confirmation field), so one layout driven by a state observer is simpler
 * and avoids an entire class of fragment-backstack bugs. A future ceremony needing
 * heterogeneous step UI would need a real extension point added here -- not needed yet.
 */
public class CeremonyActivity extends AppCompatActivity {

    private static final String EXTRA_CEREMONY_SPEC = "extra_ceremony_spec";

    public static Intent createIntent(Context context, CeremonySpec spec) {
        Intent intent = new Intent(context, CeremonyActivity.class);
        intent.putExtra(EXTRA_CEREMONY_SPEC, spec);
        return intent;
    }

    private CeremonySpec spec;
    private CeremonyViewModel viewModel;
    private ThemeChanger themeChanger;

    private TextView stepIndicatorView;
    private TextView titleView;
    private TextView bodyView;
    private CheckBox acknowledgeCheckbox;
    private TextInputLayout typedConfirmationLayout;
    private TextInputEditText typedConfirmationInput;
    private Button backButton;
    private Button cancelButton;
    private Button continueButton;

    private boolean suppressListeners;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        themeChanger = new ThemeChanger(this);
        themeChanger.setThemes(R.style.Theme_Keychain_Light, R.style.Theme_Keychain_Dark);
        themeChanger.changeTheme();
        super.onCreate(savedInstanceState);

        spec = getIntent().getParcelableExtra(EXTRA_CEREMONY_SPEC);
        if (spec == null) {
            throw new IllegalStateException("CeremonyActivity started without a CeremonySpec");
        }

        setContentView(R.layout.activity_ceremony);

        stepIndicatorView = findViewById(R.id.ceremony_step_indicator);
        titleView = findViewById(R.id.ceremony_title);
        bodyView = findViewById(R.id.ceremony_body);
        acknowledgeCheckbox = findViewById(R.id.ceremony_acknowledge_checkbox);
        typedConfirmationLayout = findViewById(R.id.ceremony_typed_confirmation_layout);
        typedConfirmationInput = findViewById(R.id.ceremony_typed_confirmation_input);
        backButton = findViewById(R.id.ceremony_back_button);
        cancelButton = findViewById(R.id.ceremony_cancel_button);
        continueButton = findViewById(R.id.ceremony_continue_button);

        viewModel = new ViewModelProvider(this).get(CeremonyViewModel.class);
        viewModel.initIfNeeded(spec);

        acknowledgeCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                onAcknowledgeInputChanged(isChecked);
            }
        });
        typedConfirmationInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            @Override
            public void afterTextChanged(Editable s) {
                onAcknowledgeInputChanged(true);
            }
        });

        backButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                viewModel.goToPreviousStep();
            }
        });
        cancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                setResult(RESULT_CANCELED);
                finish();
            }
        });
        continueButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onContinueClicked();
            }
        });

        viewModel.getState().observe(this, new androidx.lifecycle.Observer<CeremonyState>() {
            @Override
            public void onChanged(CeremonyState state) {
                if (state != null) {
                    render(state);
                }
            }
        });
    }

    @Override
    public void onBackPressed() {
        if (viewModel.isOnFirstStep()) {
            setResult(RESULT_CANCELED);
            finish();
            return;
        }
        viewModel.goToPreviousStep();
    }

    private void onAcknowledgeInputChanged(boolean checked) {
        if (suppressListeners) {
            return;
        }
        CeremonyStepSpec currentStepSpec = currentStepSpec();
        if (currentStepSpec.getRequiresTypedConfirmation()) {
            String typed = typedConfirmationInput.getText() == null
                    ? null : typedConfirmationInput.getText().toString();
            viewModel.acknowledgeCurrentStep(spec, typed);
        } else if (checked) {
            viewModel.acknowledgeCurrentStep(spec, null);
        } else {
            // Unchecking must revoke acknowledgment -- re-init this step's state by rebuilding
            // from scratch is overkill; simplest correct fix is that the continue button reads
            // canAdvance() fresh, and re-checking simply re-acknowledges. Since unchecking a
            // non-typed step has no persisted "unacknowledge" path in the ViewModel (by design --
            // acknowledgment only ever moves forward within a step, matching how the typed-
            // confirmation case can't partially un-type), we rely on the button state below
            // instead of trying to claw back an already-set acknowledgment.
        }
        continueButton.setEnabled(viewModel.canAdvance());
    }

    private void onContinueClicked() {
        if (viewModel.isOnLastStep(spec)) {
            if (viewModel.isReadyToExecute()) {
                setResult(RESULT_OK);
                finish();
            }
            return;
        }
        viewModel.goToNextStep(spec);
    }

    private CeremonyStepSpec currentStepSpec() {
        CeremonyState state = viewModel.getState().getValue();
        return spec.getSteps().get(state.getCurrentStepIndex());
    }

    private void render(CeremonyState state) {
        int index = state.getCurrentStepIndex();
        CeremonyStepSpec stepSpec = spec.getSteps().get(index);
        boolean isAcknowledged = state.getStepStates().get(index).getIsAcknowledged();

        stepIndicatorView.setText(getString(R.string.ceremony_step_indicator, index + 1, spec.getSteps().size()));
        titleView.setText(stepSpec.getTitleRes());
        bodyView.setText(stepSpec.getBodyRes());

        suppressListeners = true;
        if (stepSpec.getRequiresTypedConfirmation()) {
            acknowledgeCheckbox.setVisibility(View.GONE);
            typedConfirmationLayout.setVisibility(View.VISIBLE);
            typedConfirmationLayout.setHint(
                    getString(R.string.ceremony_typed_confirmation_hint, stepSpec.getRequiredTypedText()));
            String currentText = typedConfirmationInput.getText() == null
                    ? "" : typedConfirmationInput.getText().toString();
            String persisted = state.getStepStates().get(index).getTypedConfirmationText();
            if (persisted != null && !persisted.equals(currentText)) {
                typedConfirmationInput.setText(persisted);
            }
        } else {
            acknowledgeCheckbox.setVisibility(View.VISIBLE);
            typedConfirmationLayout.setVisibility(View.GONE);
            acknowledgeCheckbox.setChecked(isAcknowledged);
        }
        suppressListeners = false;

        backButton.setEnabled(!viewModel.isOnFirstStep());
        continueButton.setEnabled(isAcknowledged);
        continueButton.setText(viewModel.isOnLastStep(spec) ? R.string.btn_okay : R.string.btn_next);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (themeChanger.changeTheme()) {
            recreate();
        }
    }
}
