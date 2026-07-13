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

import java.util.List;

import android.os.Parcelable;

import com.google.auto.value.AutoValue;

/**
 * An ordered sequence of {@link CeremonyStepSpec}s that must all be acknowledged, in order,
 * before {@link org.sufficientlysecure.keychain.ui.ceremony.CeremonyActivity} returns {@code
 * RESULT_OK}. {@code ceremonyKind} identifies which ceremony this is (e.g.
 * {@code "revoke_primary_key"}) -- purely descriptive, not consumed by the ceremony machinery
 * itself, but useful for the consuming Activity/logging.
 */
@AutoValue
public abstract class CeremonySpec implements Parcelable {
    public abstract String getCeremonyKind();
    public abstract List<CeremonyStepSpec> getSteps();

    public static CeremonySpec create(String ceremonyKind, List<CeremonyStepSpec> steps) {
        if (steps == null || steps.isEmpty()) {
            throw new IllegalArgumentException("a ceremony must have at least one step");
        }
        return new AutoValue_CeremonySpec(ceremonyKind, steps);
    }
}
