/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
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

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentActivity;
import androidx.appcompat.app.AlertDialog;
import android.text.Html;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.DatePicker;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.util.Choice;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

public class AddSubkeyDialogFragment extends DialogFragment {

    public interface OnAlgorithmSelectedListener {
        void onAlgorithmSelected(SaveKeyringParcel.SubkeyAdd newSubkey);
    }

    public enum SupportedKeyType {
        RSA_2048, RSA_3072, RSA_4096, ECC_P256, ECC_P521, ECC_25519,

        // Composite post-quantum + classical hybrids, standardized by draft-ietf-openpgp-pqc-17.
        // Interoperable with any OpenPGP implementation that supports the draft. Each is
        // strictly single-purpose (see SaveKeyringParcel.Algorithm's doc comments): the
        // ML_KEM_* variants are encryption-only, the ML_DSA_*/SLH_DSA_* variants are
        // signing-only. No key size/curve selection applies to any of these.
        ML_KEM_768_X25519, ML_KEM_1024_X448,
        ML_DSA_65_ED25519, ML_DSA_87_ED448,
        SLH_DSA_SHAKE_128S,

        // Standalone (non-composite), closed-ecosystem, OpenKeychain private-use PQC
        // algorithms. NOT defined by draft-ietf-openpgp-pqc-17 or any other spec -- will NOT
        // interoperate with GnuPG, Sequoia, RNP, or any other OpenPGP implementation. See
        // SaveKeyringParcel#isNonStandardClosedEcosystemPqc(Algorithm), which is the
        // authoritative predicate this fragment's warning-dialog logic is driven by.
        STANDALONE_ML_KEM_768, STANDALONE_ML_KEM_1024,
        STANDALONE_ML_DSA_65, STANDALONE_ML_DSA_87
    }

    private static final String ARG_WILL_BE_MASTER_KEY = "will_be_master_key";

    private OnAlgorithmSelectedListener mAlgorithmSelectedListener;

    private CheckBox mNoExpiryCheckBox;
    private TableRow mExpiryRow;
    private DatePicker mExpiryDatePicker;
    private Spinner mKeyTypeSpinner;
    private RadioGroup mUsageRadioGroup;
    private RadioButton mUsageNone;
    private RadioButton mUsageSign;
    private RadioButton mUsageEncrypt;
    private RadioButton mUsageSignAndEncrypt;
    private RadioButton mUsageAuthentication;

    private boolean mWillBeMasterKey;

    // Position in the key-type spinner of the most recently *confirmed* selection. A standalone
    // (non-standard) PQC entry only becomes "confirmed" once the mandatory warning dialog has
    // been acknowledged; until then, this keeps pointing at whatever was selected before.
    private int mConfirmedPosition;

    public void setOnAlgorithmSelectedListener(OnAlgorithmSelectedListener listener) {
        mAlgorithmSelectedListener = listener;
    }

    public static AddSubkeyDialogFragment newInstance(boolean willBeMasterKey) {
        AddSubkeyDialogFragment frag = new AddSubkeyDialogFragment();
        Bundle args = new Bundle();

        args.putBoolean(ARG_WILL_BE_MASTER_KEY, willBeMasterKey);

        frag.setArguments(args);

        return frag;
    }


    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        final FragmentActivity context = getActivity();
        final LayoutInflater mInflater;

        mWillBeMasterKey = getArguments().getBoolean(ARG_WILL_BE_MASTER_KEY);
        mInflater = context.getLayoutInflater();

        CustomAlertDialogBuilder dialog = new CustomAlertDialogBuilder(context);

        @SuppressLint("InflateParams")
        View view = mInflater.inflate(R.layout.add_subkey_dialog, null);
        dialog.setView(view);

        mNoExpiryCheckBox = view.findViewById(R.id.add_subkey_no_expiry);
        mExpiryRow = view.findViewById(R.id.add_subkey_expiry_row);
        mExpiryDatePicker = view.findViewById(R.id.add_subkey_expiry_date_picker);
        mKeyTypeSpinner = view.findViewById(R.id.add_subkey_type);
        mUsageRadioGroup = view.findViewById(R.id.add_subkey_usage_group);
        mUsageNone = view.findViewById(R.id.add_subkey_usage_none);
        mUsageSign = view.findViewById(R.id.add_subkey_usage_sign);
        mUsageEncrypt = view.findViewById(R.id.add_subkey_usage_encrypt);
        mUsageSignAndEncrypt = view.findViewById(R.id.add_subkey_usage_sign_and_encrypt);
        mUsageAuthentication = view.findViewById(R.id.add_subkey_usage_authentication);

        if(mWillBeMasterKey) {
            dialog.setTitle(R.string.title_change_master_key);
            mUsageNone.setVisibility(View.VISIBLE);
            mUsageNone.setChecked(true);
        } else {
            dialog.setTitle(R.string.title_add_subkey);
        }

        mNoExpiryCheckBox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    mExpiryRow.setVisibility(View.GONE);
                } else {
                    mExpiryRow.setVisibility(View.VISIBLE);
                }
            }
        });

        // date picker works based on default time zone
        Calendar minDateCal = Calendar.getInstance(TimeZone.getDefault());
        minDateCal.add(Calendar.DAY_OF_YEAR, 1); // at least one day after creation (today)
        mExpiryDatePicker.setMinDate(minDateCal.getTime().getTime());

        {
            List<Choice<SupportedKeyType>> choices = buildKeyTypeChoices(getResources());
            TwoLineArrayAdapter adapter = new TwoLineArrayAdapter(context,
                    android.R.layout.simple_spinner_item, choices);
            mKeyTypeSpinner.setAdapter(adapter);
            for (int i = 0; i < choices.size(); ++i) {
                if (choices.get(i).getId() == SupportedKeyType.ECC_25519) {
                    mKeyTypeSpinner.setSelection(i);
                    mConfirmedPosition = i;
                    break;
                }
            }
        }

        dialog.setCancelable(true);

        // onClickListener are set in onStart() to override default dismiss behaviour
        dialog.setPositiveButton(android.R.string.ok, null);
        dialog.setNegativeButton(android.R.string.cancel, null);

        final AlertDialog alertDialog = dialog.show();

        mKeyTypeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                // noinspection unchecked
                SupportedKeyType keyType = ((Choice<SupportedKeyType>) parent.getSelectedItem()).getId();

                // Mandatory warning: a standalone (non-standard, closed-ecosystem) PQC algorithm
                // must not become the active selection until the user has explicitly
                // acknowledged that it will not interoperate with any other OpenPGP software.
                // Until acknowledged (or cancelled), the previously confirmed selection remains
                // in effect.
                if (position != mConfirmedPosition && isStandaloneKeyType(keyType)) {
                    showStandaloneWarningDialog(keyType, position);
                    return;
                }

                mConfirmedPosition = position;
                applySelection(keyType);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        return alertDialog;
    }

    /**
     * Shows the mandatory non-interoperability warning for standalone (non-standard,
     * closed-ecosystem) PQC algorithms, per
     * docs/superpowers/specs/2026-07-07-pqc-migration-design.md: "this warning must be shown
     * before the mode can be selected." The selection is only applied (see {@link
     * #applySelection}) if the user explicitly confirms; cancelling reverts the spinner to the
     * last confirmed position.
     */
    private void showStandaloneWarningDialog(final SupportedKeyType keyType, final int position) {
        new CustomAlertDialogBuilder(getActivity())
                .setTitle(R.string.pqc_standalone_warning_title)
                .setMessage(R.string.pqc_standalone_warning_message)
                .setCancelable(false)
                .setPositiveButton(R.string.pqc_standalone_warning_confirm, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int which) {
                        mConfirmedPosition = position;
                        applySelection(keyType);
                    }
                })
                .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int which) {
                        mKeyTypeSpinner.setSelection(mConfirmedPosition);
                    }
                })
                .show();
    }

    /**
     * Applies the usage-availability gating for a confirmed key-type selection: clears the
     * usage radio group (working around {@code RadioGroup.getCheckedRadioButtonId()} returning
     * stale state after programmatic unchecking), re-checks "None" for a master-key change, and
     * enables/disables the usage radio buttons that are incompatible with the selected
     * algorithm.
     */
    private void applySelection(SupportedKeyType keyType) {
        mUsageRadioGroup.clearCheck();

        if (mWillBeMasterKey) {
            mUsageNone.setChecked(true);
        }

        UsageAvailability availability = getUsageAvailability(keyType, mWillBeMasterKey);
        mUsageSign.setEnabled(availability.signAvailable);
        mUsageEncrypt.setEnabled(availability.encryptAvailable);
        mUsageSignAndEncrypt.setEnabled(availability.signAndEncryptAvailable);
        mUsageAuthentication.setEnabled(availability.authenticationAvailable);
    }

    @Override
    public void onStart() {
        super.onStart();    //super.onStart() is where dialog.show() is actually called on the underlying dialog, so we have to do it after this point
        AlertDialog d = (AlertDialog) getDialog();
        if (d != null) {
            Button positiveButton = d.getButton(Dialog.BUTTON_POSITIVE);
            Button negativeButton = d.getButton(Dialog.BUTTON_NEGATIVE);
            positiveButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mUsageRadioGroup.getCheckedRadioButtonId() == -1) {
                        Toast.makeText(getActivity(), R.string.edit_key_select_usage, Toast.LENGTH_LONG).show();
                        return;
                    }

                    // noinspection unchecked
                    SupportedKeyType keyType = ((Choice<SupportedKeyType>) mKeyTypeSpinner.getSelectedItem()).getId();

                    // keysize/curve only apply to RSA/ECC respectively -- every PQC algorithm
                    // (composite or standalone) takes neither (see SaveKeyringParcel.Algorithm's
                    // doc comments), so these are simply null for all of them.
                    Integer keySize = getKeySizeForKeyType(keyType);
                    Curve curve = getCurveForKeyType(keyType);
                    Algorithm algorithm = mapToAlgorithm(keyType, mUsageEncrypt.isChecked());

                    // set flags
                    int flags = 0;
                    if (mWillBeMasterKey) {
                        flags |= KeyFlags.CERTIFY_OTHER;
                    }
                    if (mUsageSign.isChecked()) {
                        flags |= KeyFlags.SIGN_DATA;
                    } else if (mUsageEncrypt.isChecked()) {
                        flags |= KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
                    } else if (mUsageSignAndEncrypt.isChecked()) {
                        flags |= KeyFlags.SIGN_DATA | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
                    } else if (mUsageAuthentication.isChecked()) {
                        flags |= KeyFlags.AUTHENTICATION;
                    }


                    long expiry;
                    if (mNoExpiryCheckBox.isChecked()) {
                        expiry = 0L;
                    } else {
                        Calendar selectedCal = Calendar.getInstance(TimeZone.getDefault());
                        //noinspection ResourceType
                        selectedCal.set(mExpiryDatePicker.getYear(),
                                mExpiryDatePicker.getMonth(), mExpiryDatePicker.getDayOfMonth());
                        // date picker uses default time zone, we need to convert to UTC
                        selectedCal.setTimeZone(TimeZone.getTimeZone("UTC"));

                        expiry = selectedCal.getTime().getTime() / 1000;
                    }

                    SaveKeyringParcel.SubkeyAdd newSubkey = SubkeyAdd.createSubkeyAdd(
                            algorithm, keySize, curve, flags, expiry
                    );
                    mAlgorithmSelectedListener.onAlgorithmSelected(newSubkey);

                    // finally, dismiss the dialogue
                    dismiss();
                }
            });
            negativeButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    dismiss();
                }
            });
        }
    }

    /**
     * Builds the key-type spinner's choice list: classical algorithms first (unchanged order),
     * then standardized composite PQC+classical hybrids ("PQC: ..."), then standalone
     * (non-standard, closed-ecosystem) PQC algorithms ("PQC (non-standard): ..."). The
     * TwoLineArrayAdapter/Choice pattern used here has no built-in support for non-selectable
     * section headers, so the grouping is conveyed by the name prefix instead.
     */
    @VisibleForTesting
    static ArrayList<Choice<SupportedKeyType>> buildKeyTypeChoices(Resources resources) {
        ArrayList<Choice<SupportedKeyType>> choices = new ArrayList<>();
        choices.add(new Choice<>(SupportedKeyType.RSA_2048, resources.getString(
                R.string.rsa_2048), resources.getString(R.string.rsa_2048_description_html)));
        choices.add(new Choice<>(SupportedKeyType.RSA_3072, resources.getString(
                R.string.rsa_3072), resources.getString(R.string.rsa_3072_description_html)));
        choices.add(new Choice<>(SupportedKeyType.RSA_4096, resources.getString(
                R.string.rsa_4096), resources.getString(R.string.rsa_4096_description_html)));
        choices.add(new Choice<>(SupportedKeyType.ECC_P256, resources.getString(
                R.string.ecc_p256), resources.getString(R.string.ecc_p256_description_html)));
        choices.add(new Choice<>(SupportedKeyType.ECC_P521, resources.getString(
                R.string.ecc_p521), resources.getString(R.string.ecc_p521_description_html)));
        choices.add(new Choice<>(SupportedKeyType.ECC_25519, resources.getString(
                R.string.ecc_25519), resources.getString(R.string.ecc_25519_description_html)));

        choices.add(new Choice<>(SupportedKeyType.ML_KEM_768_X25519, resources.getString(
                R.string.pqc_ml_kem_768_x25519), resources.getString(R.string.pqc_ml_kem_768_x25519_description_html)));
        choices.add(new Choice<>(SupportedKeyType.ML_KEM_1024_X448, resources.getString(
                R.string.pqc_ml_kem_1024_x448), resources.getString(R.string.pqc_ml_kem_1024_x448_description_html)));
        choices.add(new Choice<>(SupportedKeyType.ML_DSA_65_ED25519, resources.getString(
                R.string.pqc_ml_dsa_65_ed25519), resources.getString(R.string.pqc_ml_dsa_65_ed25519_description_html)));
        choices.add(new Choice<>(SupportedKeyType.ML_DSA_87_ED448, resources.getString(
                R.string.pqc_ml_dsa_87_ed448), resources.getString(R.string.pqc_ml_dsa_87_ed448_description_html)));
        choices.add(new Choice<>(SupportedKeyType.SLH_DSA_SHAKE_128S, resources.getString(
                R.string.pqc_slh_dsa_shake_128s), resources.getString(R.string.pqc_slh_dsa_shake_128s_description_html)));

        choices.add(new Choice<>(SupportedKeyType.STANDALONE_ML_KEM_768, resources.getString(
                R.string.pqc_standalone_ml_kem_768), resources.getString(R.string.pqc_standalone_ml_kem_768_description_html)));
        choices.add(new Choice<>(SupportedKeyType.STANDALONE_ML_KEM_1024, resources.getString(
                R.string.pqc_standalone_ml_kem_1024), resources.getString(R.string.pqc_standalone_ml_kem_1024_description_html)));
        choices.add(new Choice<>(SupportedKeyType.STANDALONE_ML_DSA_65, resources.getString(
                R.string.pqc_standalone_ml_dsa_65), resources.getString(R.string.pqc_standalone_ml_dsa_65_description_html)));
        choices.add(new Choice<>(SupportedKeyType.STANDALONE_ML_DSA_87, resources.getString(
                R.string.pqc_standalone_ml_dsa_87), resources.getString(R.string.pqc_standalone_ml_dsa_87_description_html)));

        return choices;
    }

    /**
     * True for the four standalone (non-standard, closed-ecosystem) PQC key types. Delegates to
     * {@link SaveKeyringParcel#isNonStandardClosedEcosystemPqc(Algorithm)}, the single
     * authoritative predicate for this, rather than re-implementing the judgment here.
     */
    @VisibleForTesting
    static boolean isStandaloneKeyType(SupportedKeyType keyType) {
        Algorithm algorithm = mapToAlgorithm(keyType, false);
        return algorithm != null && SaveKeyringParcel.isNonStandardClosedEcosystemPqc(algorithm);
    }

    /** Key size in bits for RSA key types; null (no key-size selection) for everything else. */
    @VisibleForTesting
    @Nullable
    static Integer getKeySizeForKeyType(SupportedKeyType keyType) {
        switch (keyType) {
            case RSA_2048:
                return 2048;
            case RSA_3072:
                return 3072;
            case RSA_4096:
                return 4096;
            default:
                return null;
        }
    }

    /** Curve for ECC key types; null (no curve selection) for everything else, PQC included. */
    @VisibleForTesting
    @Nullable
    static Curve getCurveForKeyType(SupportedKeyType keyType) {
        switch (keyType) {
            case ECC_P256:
                return Curve.NIST_P256;
            case ECC_P521:
                return Curve.NIST_P521;
            case ECC_25519:
                return Curve.CV25519;
            default:
                return null;
        }
    }

    /**
     * Maps a spinner selection to the {@link Algorithm} to construct the subkey with.
     * {@code encryptChecked} (the state of the "Encrypt" usage radio button) disambiguates the
     * dual-purpose ECC types between ECDH and ECDSA/EdDSA; every PQC type (composite and
     * standalone) is strictly single-purpose per {@code SaveKeyringParcel.Algorithm}'s doc
     * comments, so no such disambiguation applies to them.
     */
    @VisibleForTesting
    @Nullable
    static Algorithm mapToAlgorithm(SupportedKeyType keyType, boolean encryptChecked) {
        switch (keyType) {
            case RSA_2048:
            case RSA_3072:
            case RSA_4096:
                return Algorithm.RSA;
            case ECC_P256:
            case ECC_P521:
                return encryptChecked ? Algorithm.ECDH : Algorithm.ECDSA;
            case ECC_25519:
                return encryptChecked ? Algorithm.ECDH : Algorithm.EDDSA;
            case ML_KEM_768_X25519:
                return Algorithm.ML_KEM_768_X25519;
            case ML_KEM_1024_X448:
                return Algorithm.ML_KEM_1024_X448;
            case ML_DSA_65_ED25519:
                return Algorithm.ML_DSA_65_ED25519;
            case ML_DSA_87_ED448:
                return Algorithm.ML_DSA_87_ED448;
            case SLH_DSA_SHAKE_128S:
                return Algorithm.SLH_DSA_SHAKE_128S;
            case STANDALONE_ML_KEM_768:
                return Algorithm.STANDALONE_ML_KEM_768;
            case STANDALONE_ML_KEM_1024:
                return Algorithm.STANDALONE_ML_KEM_1024;
            case STANDALONE_ML_DSA_65:
                return Algorithm.STANDALONE_ML_DSA_65;
            case STANDALONE_ML_DSA_87:
                return Algorithm.STANDALONE_ML_DSA_87;
            default:
                return null;
        }
    }

    /**
     * Which usage radio buttons are compatible with a given key type. ML-KEM variants
     * (composite and standalone) are single-purpose encryption algorithms, so everything but
     * "Encrypt" is force-disabled. ML-DSA/SLH-DSA variants (composite and standalone) are
     * single-purpose signature algorithms, so "Encrypt" and "Sign & Encrypt" are force-disabled.
     * ECC retains its existing either/or (ECDH vs ECDSA/EdDSA) behaviour, gated at
     * subkey-construction time by the "Encrypt" checkbox rather than being fixed per type.
     */
    @VisibleForTesting
    static UsageAvailability getUsageAvailability(SupportedKeyType keyType, boolean willBeMasterKey) {
        boolean signAvailable = true;
        boolean encryptAvailable = true;
        boolean signAndEncryptAvailable = true;
        boolean authenticationAvailable = true;

        switch (keyType) {
            case ECC_P256:
            case ECC_P521:
            case ECC_25519:
                signAndEncryptAvailable = false;
                if (willBeMasterKey) {
                    encryptAvailable = false;
                }
                break;

            case ML_KEM_768_X25519:
            case ML_KEM_1024_X448:
            case STANDALONE_ML_KEM_768:
            case STANDALONE_ML_KEM_1024:
                signAvailable = false;
                signAndEncryptAvailable = false;
                authenticationAvailable = false;
                if (willBeMasterKey) {
                    encryptAvailable = false;
                }
                break;

            case ML_DSA_65_ED25519:
            case ML_DSA_87_ED448:
            case SLH_DSA_SHAKE_128S:
            case STANDALONE_ML_DSA_65:
            case STANDALONE_ML_DSA_87:
                encryptAvailable = false;
                signAndEncryptAvailable = false;
                break;
        }

        return new UsageAvailability(signAvailable, encryptAvailable, signAndEncryptAvailable, authenticationAvailable);
    }

    @VisibleForTesting
    static final class UsageAvailability {
        final boolean signAvailable;
        final boolean encryptAvailable;
        final boolean signAndEncryptAvailable;
        final boolean authenticationAvailable;

        UsageAvailability(boolean signAvailable, boolean encryptAvailable, boolean signAndEncryptAvailable,
                boolean authenticationAvailable) {
            this.signAvailable = signAvailable;
            this.encryptAvailable = encryptAvailable;
            this.signAndEncryptAvailable = signAndEncryptAvailable;
            this.authenticationAvailable = authenticationAvailable;
        }
    }

    private class TwoLineArrayAdapter extends ArrayAdapter<Choice<SupportedKeyType>> {
        public TwoLineArrayAdapter(Context context, int resource, List<Choice<SupportedKeyType>> objects) {
            super(context, resource, objects);
        }


        @Override
        public View getDropDownView(int position, View convertView, ViewGroup parent) {
            // inflate view if not given one
            if (convertView == null) {
                convertView = getActivity().getLayoutInflater()
                        .inflate(R.layout.two_line_spinner_dropdown_item, parent, false);
            }

            Choice c = this.getItem(position);

            TextView text1 = convertView.findViewById(android.R.id.text1);
            TextView text2 = convertView.findViewById(android.R.id.text2);

            text1.setText(c.getName());
            text2.setText(Html.fromHtml(c.getDescription()));

            return convertView;
        }
    }

}
