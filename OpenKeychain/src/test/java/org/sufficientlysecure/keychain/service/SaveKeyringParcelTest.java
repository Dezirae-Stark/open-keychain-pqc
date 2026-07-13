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

package org.sufficientlysecure.keychain.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Covers {@link SaveKeyringParcel#canSign}, {@link SaveKeyringParcel#canEncrypt}, and {@link
 * SaveKeyringParcel#canCertify} -- the single authoritative source of truth for algorithm/flag
 * legality now shared by {@link org.sufficientlysecure.keychain.ui.dialog.AddSubkeyDialogFragment}
 * (UI-level filtering) and {@link org.sufficientlysecure.keychain.pgp.PgpKeyOperation} (the
 * authoritative enforcement gate). Exhaustive over every {@link Algorithm} value, since a gap in
 * this truth table is exactly the class of bug that shipped the KEM-only-master-key hang this
 * session already found and fixed once.
 */
@RunWith(KeychainTestRunner.class)
public class SaveKeyringParcelTest {

    // Algorithms with no signing operation at all: pure key-encapsulation/encryption-only.
    private static final Algorithm[] CANNOT_SIGN = {
            Algorithm.ELGAMAL,
            Algorithm.ECDH,
            Algorithm.ML_KEM_768_X25519,
            Algorithm.ML_KEM_1024_X448,
            Algorithm.STANDALONE_ML_KEM_768,
            Algorithm.STANDALONE_ML_KEM_1024,
    };

    // Algorithms with a signing operation.
    private static final Algorithm[] CAN_SIGN = {
            Algorithm.RSA,
            Algorithm.DSA,
            Algorithm.ECDSA,
            Algorithm.EDDSA,
            Algorithm.ML_DSA_65_ED25519,
            Algorithm.ML_DSA_87_ED448,
            Algorithm.SLH_DSA_SHAKE_128S,
            Algorithm.STANDALONE_ML_DSA_65,
            Algorithm.STANDALONE_ML_DSA_87,
    };

    // Algorithms with no encryption operation at all: pure signature/certification.
    private static final Algorithm[] CANNOT_ENCRYPT = {
            Algorithm.DSA,
            Algorithm.ECDSA,
            Algorithm.EDDSA,
            Algorithm.ML_DSA_65_ED25519,
            Algorithm.ML_DSA_87_ED448,
            Algorithm.SLH_DSA_SHAKE_128S,
            Algorithm.STANDALONE_ML_DSA_65,
            Algorithm.STANDALONE_ML_DSA_87,
    };

    // Algorithms with an encryption operation.
    private static final Algorithm[] CAN_ENCRYPT = {
            Algorithm.RSA,
            Algorithm.ELGAMAL,
            Algorithm.ECDH,
            Algorithm.ML_KEM_768_X25519,
            Algorithm.ML_KEM_1024_X448,
            Algorithm.STANDALONE_ML_KEM_768,
            Algorithm.STANDALONE_ML_KEM_1024,
    };

    @Test
    public void canSign_falseOnlyForPureKemAlgorithms() {
        for (Algorithm algorithm : CANNOT_SIGN) {
            assertFalse(algorithm + " should not be able to sign", SaveKeyringParcel.canSign(algorithm));
        }
        for (Algorithm algorithm : CAN_SIGN) {
            assertTrue(algorithm + " should be able to sign", SaveKeyringParcel.canSign(algorithm));
        }
    }

    @Test
    public void canEncrypt_falseOnlyForPureSignatureAlgorithms() {
        for (Algorithm algorithm : CANNOT_ENCRYPT) {
            assertFalse(algorithm + " should not be able to encrypt", SaveKeyringParcel.canEncrypt(algorithm));
        }
        for (Algorithm algorithm : CAN_ENCRYPT) {
            assertTrue(algorithm + " should be able to encrypt", SaveKeyringParcel.canEncrypt(algorithm));
        }
    }

    @Test
    public void canCertify_isExactlyCanSign() {
        for (Algorithm algorithm : Algorithm.values()) {
            assertEquals(algorithm + ": canCertify must exactly match canSign",
                    SaveKeyringParcel.canSign(algorithm), SaveKeyringParcel.canCertify(algorithm));
        }
    }

    @Test
    public void everyAlgorithm_canSignOrCanEncryptOrBoth() {
        // No algorithm in this codebase is neither -- that would be an unusable dead entry in
        // the enum. Catches an Algorithm value accidentally left out of both truth tables above
        // if a future algorithm is added without updating canSign/canEncrypt.
        for (Algorithm algorithm : Algorithm.values()) {
            assertTrue(algorithm + " must be able to sign, encrypt, or both",
                    SaveKeyringParcel.canSign(algorithm) || SaveKeyringParcel.canEncrypt(algorithm));
        }
    }
}
