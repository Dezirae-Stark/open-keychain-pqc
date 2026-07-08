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

import java.util.List;

import android.app.Dialog;
import android.content.res.Resources;
import android.widget.RadioButton;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.FragmentActivity;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowDialog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.ui.dialog.AddSubkeyDialogFragment.SupportedKeyType;
import org.sufficientlysecure.keychain.ui.dialog.AddSubkeyDialogFragment.UsageAvailability;
import org.sufficientlysecure.keychain.util.Choice;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Covers the Phase 6 PQC UI additions to {@link AddSubkeyDialogFragment}: the new spinner
 * entries, the algorithm/keysize/curve mapping, the usage-availability gating, and the
 * mandatory non-interoperability warning for standalone (non-standard, closed-ecosystem) PQC
 * algorithms.
 * <p>
 * What this class can verify is limited to what Robolectric's simulated View/Window/Looper
 * environment supports on the local JVM -- it exercises the actual dialog/spinner/listener code
 * paths, but real visual rendering (spinner dropdown layout, HTML description rendering, dialog
 * theming) still needs a real-device pass in a later phase.
 */
@RunWith(KeychainTestRunner.class)
public class AddSubkeyDialogFragmentTest {

    // ---- Choice list construction --------------------------------------------------------

    @Test
    public void buildKeyTypeChoices_includesAllFifteenEntriesInGroupOrder() {
        Resources resources = RuntimeEnvironment.getApplication().getResources();

        List<Choice<SupportedKeyType>> choices = AddSubkeyDialogFragment.buildKeyTypeChoices(resources);

        assertEquals(15, choices.size());

        // classical algorithms come first, unchanged
        assertEquals(SupportedKeyType.RSA_2048, choices.get(0).getId());
        assertEquals(SupportedKeyType.RSA_3072, choices.get(1).getId());
        assertEquals(SupportedKeyType.RSA_4096, choices.get(2).getId());
        assertEquals(SupportedKeyType.ECC_P256, choices.get(3).getId());
        assertEquals(SupportedKeyType.ECC_P521, choices.get(4).getId());
        assertEquals(SupportedKeyType.ECC_25519, choices.get(5).getId());

        // then the standardized composite PQC group
        assertEquals(SupportedKeyType.ML_KEM_768_X25519, choices.get(6).getId());
        assertEquals(SupportedKeyType.ML_KEM_1024_X448, choices.get(7).getId());
        assertEquals(SupportedKeyType.ML_DSA_65_ED25519, choices.get(8).getId());
        assertEquals(SupportedKeyType.ML_DSA_87_ED448, choices.get(9).getId());
        assertEquals(SupportedKeyType.SLH_DSA_SHAKE_128S, choices.get(10).getId());

        // then the standalone (non-standard) group, last
        assertEquals(SupportedKeyType.STANDALONE_ML_KEM_768, choices.get(11).getId());
        assertEquals(SupportedKeyType.STANDALONE_ML_KEM_1024, choices.get(12).getId());
        assertEquals(SupportedKeyType.STANDALONE_ML_DSA_65, choices.get(13).getId());
        assertEquals(SupportedKeyType.STANDALONE_ML_DSA_87, choices.get(14).getId());
    }

    @Test
    public void buildKeyTypeChoices_pqcNamesUseClearGroupingPrefixes() {
        Resources resources = RuntimeEnvironment.getApplication().getResources();
        List<Choice<SupportedKeyType>> choices = AddSubkeyDialogFragment.buildKeyTypeChoices(resources);

        for (Choice<SupportedKeyType> choice : choices) {
            if (AddSubkeyDialogFragment.isStandaloneKeyType(choice.getId())) {
                assertTrue("standalone entry name should carry the non-standard prefix: " + choice.getName(),
                        choice.getName().startsWith("PQC (non-standard):"));
                assertTrue("standalone entry description should warn about interoperability: " + choice.getDescription(),
                        choice.getDescription().contains("will NOT interoperate"));
            } else if (isComposite(choice.getId())) {
                assertTrue("composite entry name should carry the PQC prefix: " + choice.getName(),
                        choice.getName().startsWith("PQC:"));
            }
        }
    }

    private static boolean isComposite(SupportedKeyType keyType) {
        switch (keyType) {
            case ML_KEM_768_X25519:
            case ML_KEM_1024_X448:
            case ML_DSA_65_ED25519:
            case ML_DSA_87_ED448:
            case SLH_DSA_SHAKE_128S:
                return true;
            default:
                return false;
        }
    }

    // ---- isStandaloneKeyType, driven by SaveKeyringParcel's authoritative predicate ------

    @Test
    public void isStandaloneKeyType_trueOnlyForTheFourStandaloneTypes() {
        for (SupportedKeyType keyType : SupportedKeyType.values()) {
            boolean expected = keyType == SupportedKeyType.STANDALONE_ML_KEM_768
                    || keyType == SupportedKeyType.STANDALONE_ML_KEM_1024
                    || keyType == SupportedKeyType.STANDALONE_ML_DSA_65
                    || keyType == SupportedKeyType.STANDALONE_ML_DSA_87;

            assertEquals("mismatch for " + keyType, expected, AddSubkeyDialogFragment.isStandaloneKeyType(keyType));
        }
    }

    @Test
    public void isStandaloneKeyType_agreesWithSaveKeyringParcelPredicate() {
        for (SupportedKeyType keyType : SupportedKeyType.values()) {
            Algorithm algorithm = AddSubkeyDialogFragment.mapToAlgorithm(keyType, false);
            assertEquals(SaveKeyringParcel.isNonStandardClosedEcosystemPqc(algorithm),
                    AddSubkeyDialogFragment.isStandaloneKeyType(keyType));
        }
    }

    // ---- algorithm / keysize / curve mapping ---------------------------------------------

    @Test
    public void mapToAlgorithm_compositeAndStandalonePqcTypes() {
        assertEquals(Algorithm.ML_KEM_768_X25519,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.ML_KEM_768_X25519, false));
        assertEquals(Algorithm.ML_KEM_1024_X448,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.ML_KEM_1024_X448, false));
        assertEquals(Algorithm.ML_DSA_65_ED25519,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.ML_DSA_65_ED25519, false));
        assertEquals(Algorithm.ML_DSA_87_ED448,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.ML_DSA_87_ED448, false));
        assertEquals(Algorithm.SLH_DSA_SHAKE_128S,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.SLH_DSA_SHAKE_128S, false));
        assertEquals(Algorithm.STANDALONE_ML_KEM_768,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.STANDALONE_ML_KEM_768, false));
        assertEquals(Algorithm.STANDALONE_ML_KEM_1024,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.STANDALONE_ML_KEM_1024, false));
        assertEquals(Algorithm.STANDALONE_ML_DSA_65,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.STANDALONE_ML_DSA_65, false));
        assertEquals(Algorithm.STANDALONE_ML_DSA_87,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.STANDALONE_ML_DSA_87, false));

        // the "encrypt checked" flag only disambiguates ECC; it must not affect PQC types,
        // since every PQC algorithm here is strictly single-purpose
        assertEquals(Algorithm.ML_KEM_768_X25519,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.ML_KEM_768_X25519, true));
        assertEquals(Algorithm.ML_DSA_65_ED25519,
                AddSubkeyDialogFragment.mapToAlgorithm(SupportedKeyType.ML_DSA_65_ED25519, true));
    }

    @Test
    public void keySizeAndCurve_areNullForEveryPqcType() {
        SupportedKeyType[] pqcTypes = {
                SupportedKeyType.ML_KEM_768_X25519, SupportedKeyType.ML_KEM_1024_X448,
                SupportedKeyType.ML_DSA_65_ED25519, SupportedKeyType.ML_DSA_87_ED448,
                SupportedKeyType.SLH_DSA_SHAKE_128S,
                SupportedKeyType.STANDALONE_ML_KEM_768, SupportedKeyType.STANDALONE_ML_KEM_1024,
                SupportedKeyType.STANDALONE_ML_DSA_65, SupportedKeyType.STANDALONE_ML_DSA_87,
        };
        for (SupportedKeyType keyType : pqcTypes) {
            assertNull("keySize should be null for " + keyType, AddSubkeyDialogFragment.getKeySizeForKeyType(keyType));
            assertNull("curve should be null for " + keyType, AddSubkeyDialogFragment.getCurveForKeyType(keyType));
        }

        // sanity check the pre-existing RSA/ECC behaviour is untouched
        assertEquals(Integer.valueOf(2048), AddSubkeyDialogFragment.getKeySizeForKeyType(SupportedKeyType.RSA_2048));
        assertEquals(Curve.CV25519, AddSubkeyDialogFragment.getCurveForKeyType(SupportedKeyType.ECC_25519));
    }

    // ---- usage-availability gating --------------------------------------------------------

    @Test
    public void usageAvailability_kemTypesAreEncryptOnly() {
        SupportedKeyType[] kemTypes = {
                SupportedKeyType.ML_KEM_768_X25519, SupportedKeyType.ML_KEM_1024_X448,
                SupportedKeyType.STANDALONE_ML_KEM_768, SupportedKeyType.STANDALONE_ML_KEM_1024,
        };
        for (SupportedKeyType keyType : kemTypes) {
            UsageAvailability notMaster = AddSubkeyDialogFragment.getUsageAvailability(keyType, false);
            assertFalse("sign should be disabled for " + keyType, notMaster.signAvailable);
            assertFalse("sign+encrypt should be disabled for " + keyType, notMaster.signAndEncryptAvailable);
            assertFalse("authentication should be disabled for " + keyType, notMaster.authenticationAvailable);
            assertTrue("encrypt should stay enabled for " + keyType + " as a subkey", notMaster.encryptAvailable);

            UsageAvailability asMaster = AddSubkeyDialogFragment.getUsageAvailability(keyType, true);
            assertFalse("encrypt should also be disabled for " + keyType + " as a master key",
                    asMaster.encryptAvailable);
        }
    }

    @Test
    public void usageAvailability_dsaAndSlhDsaTypesAreSignOnly() {
        SupportedKeyType[] signTypes = {
                SupportedKeyType.ML_DSA_65_ED25519, SupportedKeyType.ML_DSA_87_ED448,
                SupportedKeyType.SLH_DSA_SHAKE_128S,
                SupportedKeyType.STANDALONE_ML_DSA_65, SupportedKeyType.STANDALONE_ML_DSA_87,
        };
        for (SupportedKeyType keyType : signTypes) {
            UsageAvailability availability = AddSubkeyDialogFragment.getUsageAvailability(keyType, false);
            assertFalse("encrypt should be disabled for " + keyType, availability.encryptAvailable);
            assertFalse("sign+encrypt should be disabled for " + keyType, availability.signAndEncryptAvailable);
            assertTrue("sign should stay enabled for " + keyType, availability.signAvailable);
            assertTrue("authentication should stay enabled for " + keyType, availability.authenticationAvailable);

            // master-key-ness doesn't change anything additional for sign-only types
            UsageAvailability asMaster = AddSubkeyDialogFragment.getUsageAvailability(keyType, true);
            assertTrue(asMaster.signAvailable);
            assertFalse(asMaster.encryptAvailable);
        }
    }

    // ---- full dialog wiring: spinner -> mandatory warning -> gating ----------------------

    private AddSubkeyDialogFragment showFragment(boolean willBeMasterKey) {
        FragmentActivity activity = Robolectric.buildActivity(FragmentActivity.class).setup().get();
        AddSubkeyDialogFragment fragment = AddSubkeyDialogFragment.newInstance(willBeMasterKey);
        fragment.setOnAlgorithmSelectedListener(newSubkey -> { });
        fragment.show(activity.getSupportFragmentManager(), "add_subkey_test");
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();
        return fragment;
    }

    private int findPosition(Spinner spinner, SupportedKeyType keyType) {
        for (int i = 0; i < spinner.getAdapter().getCount(); i++) {
            @SuppressWarnings("unchecked")
            Choice<SupportedKeyType> choice = (Choice<SupportedKeyType>) spinner.getAdapter().getItem(i);
            if (choice.getId() == keyType) {
                return i;
            }
        }
        throw new AssertionError("key type not found in spinner: " + keyType);
    }

    @Test
    public void selectingStandaloneEntry_showsMandatoryNonInteropWarning() {
        AddSubkeyDialogFragment fragment = showFragment(false);
        Dialog mainDialog = fragment.getDialog();
        Spinner spinner = mainDialog.findViewById(R.id.add_subkey_type);

        int standalonePosition = findPosition(spinner, SupportedKeyType.STANDALONE_ML_DSA_65);
        spinner.setSelection(standalonePosition);
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        Dialog latestDialog = ShadowDialog.getLatestDialog();
        assertNotNull("a warning dialog should have been shown", latestDialog);
        assertNotSame("the warning dialog must be a separate dialog stacked on top of the main one",
                mainDialog, latestDialog);

        TextView messageView = latestDialog.findViewById(android.R.id.message);
        assertNotNull(messageView);
        String expectedMessage = RuntimeEnvironment.getApplication().getResources()
                .getString(R.string.pqc_standalone_warning_message);
        assertEquals(expectedMessage, messageView.getText().toString());

        // the usage radio buttons must not have been switched to the (not-yet-confirmed)
        // standalone algorithm's gating while the warning is still pending
        RadioButton signRadio = mainDialog.findViewById(R.id.add_subkey_usage_sign);
        assertTrue("sign should still be enabled -- selection is not confirmed yet", signRadio.isEnabled());
    }

    @Test
    public void cancellingWarning_revertsSpinnerAndLeavesGatingUnchanged() {
        AddSubkeyDialogFragment fragment = showFragment(false);
        Dialog mainDialog = fragment.getDialog();
        Spinner spinner = mainDialog.findViewById(R.id.add_subkey_type);
        int originalPosition = spinner.getSelectedItemPosition();

        int standalonePosition = findPosition(spinner, SupportedKeyType.STANDALONE_ML_KEM_768);
        spinner.setSelection(standalonePosition);
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        AlertDialog warningDialog = (AlertDialog) ShadowDialog.getLatestDialog();
        warningDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        assertEquals("cancelling the warning must revert the spinner to the prior selection",
                originalPosition, spinner.getSelectedItemPosition());
    }

    @Test
    public void confirmingWarning_appliesStandaloneKemGatingAndProducesStandaloneAlgorithm() {
        final SubkeyAdd[] captured = new SubkeyAdd[1];
        FragmentActivity activity = Robolectric.buildActivity(FragmentActivity.class).setup().get();
        AddSubkeyDialogFragment fragment = AddSubkeyDialogFragment.newInstance(false);
        fragment.setOnAlgorithmSelectedListener(newSubkey -> captured[0] = newSubkey);
        fragment.show(activity.getSupportFragmentManager(), "add_subkey_test_2");
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        Dialog mainDialog = fragment.getDialog();
        Spinner spinner = mainDialog.findViewById(R.id.add_subkey_type);

        int standalonePosition = findPosition(spinner, SupportedKeyType.STANDALONE_ML_KEM_768);
        spinner.setSelection(standalonePosition);
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        AlertDialog warningDialog = (AlertDialog) ShadowDialog.getLatestDialog();
        warningDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        assertEquals("selection should now be confirmed on the standalone entry",
                standalonePosition, spinner.getSelectedItemPosition());

        RadioButton signRadio = mainDialog.findViewById(R.id.add_subkey_usage_sign);
        RadioButton encryptRadio = mainDialog.findViewById(R.id.add_subkey_usage_encrypt);
        RadioButton signAndEncryptRadio = mainDialog.findViewById(R.id.add_subkey_usage_sign_and_encrypt);
        RadioButton authRadio = mainDialog.findViewById(R.id.add_subkey_usage_authentication);
        assertFalse(signRadio.isEnabled());
        assertTrue(encryptRadio.isEnabled());
        assertFalse(signAndEncryptRadio.isEnabled());
        assertFalse(authRadio.isEnabled());

        encryptRadio.performClick();

        AlertDialog fullDialog = (AlertDialog) mainDialog;
        fullDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();

        assertNotNull("listener should have received the new subkey", captured[0]);
        assertEquals(Algorithm.STANDALONE_ML_KEM_768, captured[0].getAlgorithm());
        assertNull(captured[0].getKeySize());
        assertNull(captured[0].getCurve());
        assertTrue(captured[0].canEncrypt());
    }

    @Test
    public void selectingCompositePqcEntry_appliesGatingWithoutAnyWarning() {
        AddSubkeyDialogFragment fragment = showFragment(false);
        Dialog mainDialog = fragment.getDialog();
        Spinner spinner = mainDialog.findViewById(R.id.add_subkey_type);

        Dialog dialogBeforeSelection = ShadowDialog.getLatestDialog();

        int position = findPosition(spinner, SupportedKeyType.ML_DSA_65_ED25519);
        spinner.setSelection(position);
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        assertEquals("no extra dialog should be shown for a standardized composite algorithm",
                dialogBeforeSelection, ShadowDialog.getLatestDialog());

        RadioButton signRadio = mainDialog.findViewById(R.id.add_subkey_usage_sign);
        RadioButton encryptRadio = mainDialog.findViewById(R.id.add_subkey_usage_encrypt);
        assertTrue(signRadio.isEnabled());
        assertFalse(encryptRadio.isEnabled());
    }
}
