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

package org.sufficientlysecure.keychain.ui.dialog;

import java.util.ArrayList;
import java.util.List;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentActivity;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.pgp.RawPqcKeyImport;
import org.sufficientlysecure.keychain.pgp.RawPqcKeyImport.RawPqcKeyImportException;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;

/**
 * Raw PQC key material import UI: collects an algorithm selection, a hex-encoded seed (and,
 * for composite algorithms, a hex-encoded classical seed), and a user ID, then hands the
 * resulting {@link SaveKeyringParcel} to a host-supplied {@link OnRawPqcKeyImportListener} --
 * this fragment does not itself execute the key creation, mirroring {@link
 * AddSubkeyDialogFragment}'s separation of "collect and validate input, produce a parcel" from
 * "actually run the crypto operation", which the host is responsible for (see {@code
 * ImportKeysActivity}, which runs the returned parcel through {@code EditKeyOperation} via the
 * standard {@code CryptoOperationHelper<SaveKeyringParcel, EditKeyResult>} pattern already used
 * for normal in-app key generation in {@code CreateKeyFinalFragment}).
 * <p>
 * All actual parsing/validation is delegated to {@link RawPqcKeyImport#parseFields} -- this
 * class owns only the widgets and the algorithm-to-display-name mapping, it does not duplicate
 * any seed-length or format rules.
 * <p>
 * <b>Mandatory security warning.</b> Supplying your own seed material bypasses this app's own
 * key-generation randomness entirely -- the resulting key's security depends wholly on the
 * secrecy and entropy quality of the seed the caller provides, with no way for this class (or
 * anything downstream of it) to detect a weak, reused, or previously-exposed seed. Before the
 * parsed request is ever handed to the listener, {@link #showSecurityWarningDialog} must be
 * explicitly confirmed -- this reuses {@code AddSubkeyDialogFragment}'s established
 * non-cancelable-confirmation pattern for its standalone-PQC warning ({@code
 * showStandaloneWarningDialog}) rather than inventing a new confirmation UX for what is
 * conceptually the same kind of "this is unusual and you need to affirmatively opt in" moment.
 * <p>
 * <b>Menu-entry prominence (deliberate choice, not an oversight).</b> This feature ships as a
 * normal (not debug-gated) overflow menu item, labeled "(advanced)" in the menu title specifically
 * -- see {@code R.string#raw_pqc_import_menu_title} -- distinct from this dialog's own, plainer
 * title. Two considered alternatives were rejected: hiding it behind a debug/developer-options
 * flag has no precedent anywhere else in this codebase (the standalone-PQC and other advanced
 * options are also always-visible, gated only by an in-context warning dialog, not by build
 * variant or a settings toggle), so adding one here would be a new, inconsistent convention
 * introduced for this feature alone; leaving the entry completely unlabeled (as it shipped
 * originally) gave no signal at all that this is an expert path with real footguns, before the
 * user even opens the dialog. Labeling the menu entry itself, on top of the in-dialog
 * confirmation, was judged the smallest change consistent with the rest of the app.
 */
public class RawPqcKeyImportDialogFragment extends DialogFragment {

    public interface OnRawPqcKeyImportListener {
        /**
         * @param parcel ready to be run through {@code PgpKeyOperation#createSecretKeyRing}
         *        (e.g. via {@code EditKeyOperation#execute})
         * @param syntheticMasterKeyGenerated true iff a freshly, randomly generated (NOT
         *        seed-derived) composite ML-DSA-65+Ed25519 master key was added ahead of the
         *        raw-imported key --
         *        see {@link RawPqcKeyImport}'s class Javadoc, "Known limitation" section. The
         *        host should surface this to the user (e.g. via {@link
         *        R.string#raw_pqc_import_synthetic_master_notice}) rather than silently
         *        proceeding as if the whole key were seed-derived.
         */
        void onRawPqcKeyImportReady(SaveKeyringParcel parcel, boolean syntheticMasterKeyGenerated);
    }

    /** The 9 PQC algorithms selectable here, in spinner order -- standardized/composite first
     * (mirroring {@link AddSubkeyDialogFragment}'s ordering), non-standard/standalone last. */
    private static final Algorithm[] SELECTABLE_ALGORITHMS = {
            Algorithm.ML_KEM_768_X25519,
            Algorithm.ML_KEM_1024_X448,
            Algorithm.ML_DSA_65_ED25519,
            Algorithm.ML_DSA_87_ED448,
            Algorithm.SLH_DSA_SHAKE_128S,
            Algorithm.STANDALONE_ML_KEM_768,
            Algorithm.STANDALONE_ML_KEM_1024,
            Algorithm.STANDALONE_ML_DSA_65,
            Algorithm.STANDALONE_ML_DSA_87,
    };

    private OnRawPqcKeyImportListener mListener;

    private Spinner mAlgorithmSpinner;
    private View mClassicalSeedRow;
    private EditText mClassicalSeedHexEdit;
    private EditText mSeedHexEdit;
    private EditText mUserIdEdit;
    private EditText mCreationTimeSecondsEdit;

    public static RawPqcKeyImportDialogFragment newInstance() {
        return new RawPqcKeyImportDialogFragment();
    }

    /** Must be called before {@code show()} -- see {@link AddSubkeyDialogFragment}'s identical
     * listener-attachment convention, which this mirrors. */
    public void setOnRawPqcKeyImportListener(OnRawPqcKeyImportListener listener) {
        mListener = listener;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        final FragmentActivity context = getActivity();
        LayoutInflater inflater = context.getLayoutInflater();

        CustomAlertDialogBuilder dialog = new CustomAlertDialogBuilder(context);

        @SuppressLint("InflateParams")
        View view = inflater.inflate(R.layout.raw_pqc_key_import_dialog, null);
        dialog.setView(view);
        dialog.setTitle(R.string.raw_pqc_import_title);

        mAlgorithmSpinner = view.findViewById(R.id.raw_pqc_import_algorithm_spinner);
        mClassicalSeedRow = view.findViewById(R.id.raw_pqc_import_classical_seed_row);
        mClassicalSeedHexEdit = view.findViewById(R.id.raw_pqc_import_classical_seed_hex);
        mSeedHexEdit = view.findViewById(R.id.raw_pqc_import_seed_hex);
        mUserIdEdit = view.findViewById(R.id.raw_pqc_import_user_id);
        mCreationTimeSecondsEdit = view.findViewById(R.id.raw_pqc_import_creation_time_seconds);

        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                context, android.R.layout.simple_spinner_item, algorithmDisplayNames(context.getResources()));
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        mAlgorithmSpinner.setAdapter(adapter);
        mAlgorithmSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View selectedView, int position, long id) {
                updateClassicalSeedRowVisibility(SELECTABLE_ALGORITHMS[position]);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
        updateClassicalSeedRowVisibility(SELECTABLE_ALGORITHMS[0]);

        dialog.setCancelable(true);
        // onClickListener is set in onStart() to override default dismiss-on-click behaviour,
        // so a validation failure can keep the dialog open -- same convention as
        // AddSubkeyDialogFragment.
        dialog.setPositiveButton(R.string.raw_pqc_import_button, null);
        dialog.setNegativeButton(android.R.string.cancel, null);

        return dialog.show();
    }

    private void updateClassicalSeedRowVisibility(Algorithm algorithm) {
        mClassicalSeedRow.setVisibility(
                RawPqcKeyImport.isCompositeAlgorithm(algorithm) ? View.VISIBLE : View.GONE);
    }

    private static List<String> algorithmDisplayNames(Resources resources) {
        List<String> names = new ArrayList<>(SELECTABLE_ALGORITHMS.length);
        for (Algorithm algorithm : SELECTABLE_ALGORITHMS) {
            names.add(resources.getString(algorithmDisplayNameResId(algorithm)));
        }
        return names;
    }

    /** Reuses the exact same display-name string resources {@link AddSubkeyDialogFragment}'s
     * key-type spinner uses, for consistency -- this is deliberately not a new, separately
     * translated vocabulary for the same 9 algorithms. */
    private static int algorithmDisplayNameResId(Algorithm algorithm) {
        switch (algorithm) {
            case ML_KEM_768_X25519:
                return R.string.pqc_ml_kem_768_x25519;
            case ML_KEM_1024_X448:
                return R.string.pqc_ml_kem_1024_x448;
            case ML_DSA_65_ED25519:
                return R.string.pqc_ml_dsa_65_ed25519;
            case ML_DSA_87_ED448:
                return R.string.pqc_ml_dsa_87_ed448;
            case SLH_DSA_SHAKE_128S:
                return R.string.pqc_slh_dsa_shake_128s;
            case STANDALONE_ML_KEM_768:
                return R.string.pqc_standalone_ml_kem_768;
            case STANDALONE_ML_KEM_1024:
                return R.string.pqc_standalone_ml_kem_1024;
            case STANDALONE_ML_DSA_65:
                return R.string.pqc_standalone_ml_dsa_65;
            case STANDALONE_ML_DSA_87:
                return R.string.pqc_standalone_ml_dsa_87;
            default:
                throw new IllegalArgumentException("not a selectable raw-import algorithm: " + algorithm);
        }
    }

    @Override
    public void onStart() {
        super.onStart(); // this is where dialog.show() is actually called on the underlying
        // dialog, so the button listener below has to be attached after this point (see
        // AddSubkeyDialogFragment.onStart's identical comment).
        AlertDialog d = (AlertDialog) getDialog();
        if (d == null) {
            return;
        }
        Button positiveButton = d.getButton(Dialog.BUTTON_POSITIVE);
        positiveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onImportClicked();
            }
        });
    }

    private void onImportClicked() {
        int position = mAlgorithmSpinner.getSelectedItemPosition();
        if (position < 0 || position >= SELECTABLE_ALGORITHMS.length) {
            return;
        }
        Algorithm algorithm = SELECTABLE_ALGORITHMS[position];

        String classicalSeedHex = mClassicalSeedHexEdit.getText().toString().trim();
        String seedHex = mSeedHexEdit.getText().toString().trim();
        String userId = mUserIdEdit.getText().toString().trim();
        String creationTimeSecondsText = mCreationTimeSecondsEdit.getText().toString().trim();

        Long creationTimeSeconds = null;
        if (!creationTimeSecondsText.isEmpty()) {
            try {
                creationTimeSeconds = Long.parseLong(creationTimeSecondsText);
            } catch (NumberFormatException e) {
                Toast.makeText(getActivity(), R.string.raw_pqc_import_creation_time_invalid,
                        Toast.LENGTH_LONG).show();
                return;
            }
        }

        final RawPqcKeyImport.ParsedRequest request;
        try {
            request = RawPqcKeyImport.parseFields(
                    algorithm.name(), classicalSeedHex, seedHex, userId, creationTimeSeconds);
        } catch (RawPqcKeyImportException e) {
            Toast.makeText(getActivity(), e.getMessage(), Toast.LENGTH_LONG).show();
            return;
        }

        // Fields are valid -- but the request must not be handed to the listener until the
        // caller has explicitly acknowledged the security warning below. See this class's
        // Javadoc, "Mandatory security warning".
        showSecurityWarningDialog(request);
    }

    /**
     * Mandatory, non-cancelable confirmation that the caller understands raw seed import
     * bypasses this app's own key-generation randomness -- see this class's Javadoc. Mirrors
     * {@link AddSubkeyDialogFragment#showStandaloneWarningDialog} exactly: {@code
     * setCancelable(false)} plus an explicit positive/negative button pair (rather than a
     * dismissible dialog or static in-layout text) so the acknowledgement is a real,
     * unavoidable step rather than something a user can accidentally tap past. Declining leaves
     * the underlying import dialog open and unchanged, exactly like the standalone-PQC warning's
     * "revert to last confirmed selection" behavior.
     */
    private void showSecurityWarningDialog(final RawPqcKeyImport.ParsedRequest request) {
        new CustomAlertDialogBuilder(getActivity())
                .setTitle(R.string.raw_pqc_import_warning_title)
                .setMessage(R.string.raw_pqc_import_warning_message)
                .setCancelable(false)
                .setPositiveButton(R.string.raw_pqc_import_warning_confirm, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int which) {
                        RawPqcKeyImport.BuiltParcel built = RawPqcKeyImport.buildSaveKeyringParcel(request);
                        if (mListener != null) {
                            mListener.onRawPqcKeyImportReady(built.parcel, built.syntheticMasterKeyGenerated);
                        }
                        dismiss();
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}
