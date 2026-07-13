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
import java.util.Collections;

import android.content.Context;

import org.sufficientlysecure.keychain.R;

/**
 * The pre-flight checklist gate for key deletion -- see {@code DeleteKeyDialogActivity}. Secret
 * key deletion (unrecoverable private material) gets the full typed-confirmation ceremony;
 * public-key-only deletion (re-importable from a keyserver or backup) gets a single lighter
 * acknowledgment step, matching the actual difference in stakes between the two operations.
 */
public final class DeleteKeyCeremony {
    public static final String CEREMONY_KIND_SECRET = "delete_secret_key";
    public static final String CEREMONY_KIND_PUBLIC = "delete_public_key";

    private DeleteKeyCeremony() {}

    public static CeremonySpec buildSpec(Context context, boolean hasSecret) {
        if (hasSecret) {
            return CeremonySpec.create(CEREMONY_KIND_SECRET, Arrays.asList(
                    CeremonyStepSpec.create("consequences",
                            R.string.ceremony_delete_secret_step1_title, R.string.ceremony_delete_secret_step1_body),
                    CeremonyStepSpec.create("backup_check",
                            R.string.ceremony_delete_secret_step2_title, R.string.ceremony_delete_secret_step2_body),
                    CeremonyStepSpec.createWithTypedConfirmation("typed_confirmation",
                            R.string.ceremony_delete_secret_step3_title, R.string.ceremony_delete_secret_step3_body,
                            context.getString(R.string.ceremony_delete_confirmation_text))
            ));
        }
        return CeremonySpec.create(CEREMONY_KIND_PUBLIC, Collections.singletonList(
                CeremonyStepSpec.create("consequences",
                        R.string.ceremony_delete_public_step1_title, R.string.ceremony_delete_public_step1_body)
        ));
    }
}
