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
import androidx.annotation.StringRes;

import com.google.auto.value.AutoValue;

/**
 * Declares one step of a {@link CeremonySpec} -- what it says, and whether acknowledging it
 * requires typing a specific confirmation string (for the most irreversible ceremonies) or just
 * an acknowledgment checkbox. Pure declaration, no mutable state -- see {@link CeremonyStepState}
 * for the per-instance acknowledgment state this is paired with.
 */
@AutoValue
public abstract class CeremonyStepSpec implements Parcelable {
    public abstract String getStepId();
    @StringRes public abstract int getTitleRes();
    @StringRes public abstract int getBodyRes();
    public abstract boolean getRequiresTypedConfirmation();
    @Nullable public abstract String getRequiredTypedText();

    public static CeremonyStepSpec create(String stepId, @StringRes int titleRes, @StringRes int bodyRes) {
        return new AutoValue_CeremonyStepSpec(stepId, titleRes, bodyRes, false, null);
    }

    public static CeremonyStepSpec createWithTypedConfirmation(
            String stepId, @StringRes int titleRes, @StringRes int bodyRes, String requiredTypedText) {
        if (requiredTypedText == null || requiredTypedText.isEmpty()) {
            throw new IllegalArgumentException("requiredTypedText must be non-empty");
        }
        return new AutoValue_CeremonyStepSpec(stepId, titleRes, bodyRes, true, requiredTypedText);
    }
}
