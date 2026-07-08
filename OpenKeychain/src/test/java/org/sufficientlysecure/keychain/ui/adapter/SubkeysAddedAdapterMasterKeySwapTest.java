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

package org.sufficientlysecure.keychain.ui.adapter;


import java.util.ArrayList;

import android.app.Dialog;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.RadioButton;
import android.widget.Spinner;

import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.FragmentActivity;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowDialog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.ui.dialog.AddSubkeyDialogFragment.SupportedKeyType;
import org.sufficientlysecure.keychain.util.Choice;

import static org.bouncycastle.bcpg.sig.KeyFlags.CERTIFY_OTHER;
import static org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_COMMS;
import static org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_STORAGE;
import static org.bouncycastle.bcpg.sig.KeyFlags.SIGN_DATA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

/**
 * Confirms the Phase 6b research finding that a v6-capable master-key choice is already
 * reachable during <em>new</em>-key creation, not just for already-existing keys: {@code
 * CreateKeyFinalFragment}'s "menu_create_key_edit" action launches {@code EditKeyActivity} /
 * {@code EditKeyFragment} on the in-progress (not-yet-created) {@code SaveKeyringParcel}, whose
 * subkey list is backed directly by this adapter -- and tapping the bold position-0 row here is
 * the exact "change master key" entry point, wired to {@code AddSubkeyDialogFragment}'s
 * {@code mWillBeMasterKey=true} mode, which Phase 6 already made PQC-capable.
 * <p>
 * This test drives that exact adapter code (not a re-implementation of it) end-to-end: tap the
 * master-key row, pick a v6-only PQC signing algorithm from the real dialog, confirm, and verify
 * the adapter's backing list -- the same {@code ArrayList<SubkeyAdd>} {@code EditKeyFragment}
 * hands to {@code SaveKeyringParcel.Builder} on save -- now has that PQC algorithm at position
 * 0, with the untouched default subkey still present at position 1 (the exact "leftover
 * default subkey" shape {@link org.sufficientlysecure.keychain.pgp.PgpKeyOperation}'s
 * version-consistency fix handles at generation time).
 */
@RunWith(KeychainTestRunner.class)
public class SubkeysAddedAdapterMasterKeySwapTest {

    private ArrayList<SubkeyAdd> defaultSubkeys() {
        ArrayList<SubkeyAdd> subkeys = new ArrayList<>();
        subkeys.add(SubkeyAdd.createSubkeyAdd(
                Algorithm.EDDSA, null, Curve.CV25519, CERTIFY_OTHER | SIGN_DATA, 0L));
        subkeys.add(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, null, Curve.CV25519, ENCRYPT_COMMS | ENCRYPT_STORAGE, 0L));
        return subkeys;
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

    /**
     * Tapping the bold position-0 row (the master key) must open the "change master key"
     * dialog in {@code mWillBeMasterKey=true} mode -- this is the reachability claim itself,
     * exercised directly rather than assumed.
     */
    @Test
    public void tappingMasterKeyRow_opensChangeMasterKeyDialog() {
        FragmentActivity activity = Robolectric.buildActivity(FragmentActivity.class).setup().get();
        ArrayList<SubkeyAdd> subkeys = defaultSubkeys();
        SubkeysAddedAdapter adapter = new SubkeysAddedAdapter(activity, subkeys);

        FrameLayout parent = new FrameLayout(activity);
        View masterRowView = adapter.getView(0, null, parent);
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        Dialog dialogBeforeTap = ShadowDialog.getLatestDialog();
        masterRowView.performClick();
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        Dialog masterKeyDialog = ShadowDialog.getLatestDialog();
        assertNotNull("tapping the master-key row must open a dialog", masterKeyDialog);
        assertNotSame("a new dialog must have been shown", dialogBeforeTap, masterKeyDialog);

        // confirm this is specifically AddSubkeyDialogFragment's dialog, in its
        // mWillBeMasterKey=true mode: the key-type spinner is present, and "Usage: None" is
        // force-checked by default for a master-key change (see applySelection's Javadoc).
        Spinner spinner = masterKeyDialog.findViewById(R.id.add_subkey_type);
        assertNotNull("the change-master-key dialog must expose the algorithm spinner", spinner);
        RadioButton usageNone = masterKeyDialog.findViewById(R.id.add_subkey_usage_none);
        assertNotNull("master-key mode must show the 'None' usage option", usageNone);
        assertEquals(View.VISIBLE, usageNone.getVisibility());
        assertTrue("master-key mode force-checks 'Usage: None' by default", usageNone.isChecked());
    }

    /**
     * The actual reachability + correctness test: pick composite ML-DSA-65+Ed25519 (a
     * v6-only PQC signing algorithm) as the new master key through the real dialog, confirm,
     * and verify the adapter's backing subkey list -- the same list {@code EditKeyFragment}
     * feeds back into {@code SaveKeyringParcel.Builder} -- now has it at position 0, with the
     * original default ECDH subkey still untouched at position 1.
     */
    @Test
    public void selectingPqcSigningAlgorithmAsMasterKey_replacesPositionZeroOnly() {
        FragmentActivity activity = Robolectric.buildActivity(FragmentActivity.class).setup().get();
        ArrayList<SubkeyAdd> subkeys = defaultSubkeys();
        SubkeyAdd originalEcdhSubkey = subkeys.get(1);
        SubkeysAddedAdapter adapter = new SubkeysAddedAdapter(activity, subkeys);

        FrameLayout parent = new FrameLayout(activity);
        View masterRowView = adapter.getView(0, null, parent);
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        masterRowView.performClick();
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        AlertDialog masterKeyDialog = (AlertDialog) ShadowDialog.getLatestDialog();
        assertNotNull(masterKeyDialog);

        Spinner spinner = masterKeyDialog.findViewById(R.id.add_subkey_type);
        int mlDsaPosition = findPosition(spinner, SupportedKeyType.ML_DSA_65_ED25519);
        spinner.setSelection(mlDsaPosition);
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        // per the Phase 6b research: master-key mode force-checks "Usage: None" by default,
        // so pick "Sign" explicitly to get a certify+sign master key (matching the original
        // default master key's usage combination) -- exercising exactly the UX wrinkle the
        // research flagged, rather than silently relying on the force-checked default.
        RadioButton signRadio = masterKeyDialog.findViewById(R.id.add_subkey_usage_sign);
        assertTrue("Sign must be selectable for a PQC signing algorithm chosen as master key",
                signRadio.isEnabled());
        signRadio.performClick();

        masterKeyDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle();

        assertEquals("adapter must still have exactly two entries", 2, adapter.getCount());

        SubkeyAdd newMasterKey = adapter.getItem(0);
        assertEquals("position 0 must now be the chosen v6-only PQC signing algorithm",
                Algorithm.ML_DSA_65_ED25519, newMasterKey.getAlgorithm());
        assertEquals("the new master key must carry CERTIFY_OTHER",
                CERTIFY_OTHER, newMasterKey.getFlags() & CERTIFY_OTHER);
        assertEquals("the new master key must carry SIGN_DATA, since Sign was explicitly picked",
                SIGN_DATA, newMasterKey.getFlags() & SIGN_DATA);

        SubkeyAdd stillPresentEcdhSubkey = adapter.getItem(1);
        assertEquals("the original default ECDH subkey must be untouched by the master-key swap",
                originalEcdhSubkey, stillPresentEcdhSubkey);
    }
}
