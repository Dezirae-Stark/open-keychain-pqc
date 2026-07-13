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

package org.sufficientlysecure.keychain.ui;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.junit.Test;
import org.sufficientlysecure.keychain.pgp.AlgorithmFamily;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Covers the pure decision logic behind B5 (the algorithm-diversity advisory) --
 * {@link CreateKeyFinalFragment#getSoleSigningFamilyOrNull}. The dialog-display side of
 * {@code checkAlgorithmDiversity()} needs a live Fragment/Activity and isn't covered here; this
 * is specifically the "should the advisory fire at all" logic.
 */
public class CreateKeyFinalFragmentAlgorithmDiversityTest {

    @Test
    public void singleClassicalSigningSubkey_returnsClassical() {
        SaveKeyringParcel parcel = parcelOf(
                subkey(Algorithm.ECDSA, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA));

        AlgorithmFamily result = CreateKeyFinalFragment.getSoleSigningFamilyOrNull(parcel);

        assertEquals(AlgorithmFamily.CLASSICAL, result);
    }

    @Test
    public void certifyAndSignBothLattice_returnsLattice() {
        SaveKeyringParcel parcel = parcelOf(
                subkey(Algorithm.ML_DSA_65_ED25519, KeyFlags.CERTIFY_OTHER),
                subkey(Algorithm.ML_DSA_65_ED25519, KeyFlags.SIGN_DATA));

        AlgorithmFamily result = CreateKeyFinalFragment.getSoleSigningFamilyOrNull(parcel);

        assertEquals(AlgorithmFamily.LATTICE, result);
    }

    @Test
    public void twoDistinctSigningFamilies_returnsNull() {
        // A lattice certify/sign key plus a hash-based signing subkey -- already diverse,
        // so the advisory must not fire.
        SaveKeyringParcel parcel = parcelOf(
                subkey(Algorithm.ML_DSA_65_ED25519, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA),
                subkey(Algorithm.SLH_DSA_SHAKE_128S, KeyFlags.SIGN_DATA));

        AlgorithmFamily result = CreateKeyFinalFragment.getSoleSigningFamilyOrNull(parcel);

        assertNull("two distinct signing families must not trigger the advisory", result);
    }

    @Test
    public void encryptOnlySubkey_doesNotCountTowardSigningFamilies() {
        // certify+sign is CLASSICAL; an ML-KEM encrypt-only subkey (LATTICE) must not be
        // counted, since it can't sign -- otherwise this would spuriously look "diverse".
        SaveKeyringParcel parcel = parcelOf(
                subkey(Algorithm.ECDSA, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA),
                subkey(Algorithm.ML_KEM_768_X25519, KeyFlags.ENCRYPT_COMMS));

        AlgorithmFamily result = CreateKeyFinalFragment.getSoleSigningFamilyOrNull(parcel);

        assertEquals("an encrypt-only subkey must not be counted as a signing family",
                AlgorithmFamily.CLASSICAL, result);
    }

    @Test
    public void noSigningCapableSubkeys_returnsNull() {
        SaveKeyringParcel parcel = parcelOf(
                subkey(Algorithm.ML_KEM_768_X25519, KeyFlags.ENCRYPT_COMMS));

        AlgorithmFamily result = CreateKeyFinalFragment.getSoleSigningFamilyOrNull(parcel);

        assertNull(result);
    }

    private static SubkeyAdd subkey(Algorithm algorithm, int flags) {
        return SubkeyAdd.createSubkeyAdd(algorithm, 0, Curve.NIST_P256, flags, 0L);
    }

    private static SaveKeyringParcel parcelOf(SubkeyAdd... subkeys) {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        for (SubkeyAdd subkey : subkeys) {
            builder.addSubkeyAdd(subkey);
        }
        return builder.build();
    }
}
