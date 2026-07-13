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

package org.sufficientlysecure.keychain.pgp;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/** Exhaustive over every {@link Algorithm} value -- a gap here would silently make the B5
 *  algorithm-diversity advisory blind to some algorithm. */
@RunWith(KeychainTestRunner.class)
public class AlgorithmFamilyTest {

    private static final Algorithm[] HASH_BASED_ALGORITHMS = {
            Algorithm.SLH_DSA_SHAKE_128S,
    };

    private static final Algorithm[] LATTICE_ALGORITHMS = {
            Algorithm.ML_KEM_768_X25519,
            Algorithm.ML_KEM_1024_X448,
            Algorithm.ML_DSA_65_ED25519,
            Algorithm.ML_DSA_87_ED448,
            Algorithm.STANDALONE_ML_KEM_768,
            Algorithm.STANDALONE_ML_KEM_1024,
            Algorithm.STANDALONE_ML_DSA_65,
            Algorithm.STANDALONE_ML_DSA_87,
    };

    private static final Algorithm[] CLASSICAL_ALGORITHMS = {
            Algorithm.RSA, Algorithm.DSA, Algorithm.ELGAMAL,
            Algorithm.ECDSA, Algorithm.ECDH, Algorithm.EDDSA,
    };

    @Test
    public void familyOf_hashBasedOnlyForSlhDsa() {
        for (Algorithm algorithm : HASH_BASED_ALGORITHMS) {
            assertEquals(algorithm + " should be HASH_BASED", AlgorithmFamily.HASH_BASED, AlgorithmFamily.familyOf(algorithm));
        }
    }

    @Test
    public void familyOf_latticeForEveryMlKemAndMlDsaVariant() {
        for (Algorithm algorithm : LATTICE_ALGORITHMS) {
            assertEquals(algorithm + " should be LATTICE", AlgorithmFamily.LATTICE, AlgorithmFamily.familyOf(algorithm));
        }
    }

    @Test
    public void familyOf_classicalForEveryNonPqcAlgorithm() {
        for (Algorithm algorithm : CLASSICAL_ALGORITHMS) {
            assertEquals(algorithm + " should be CLASSICAL", AlgorithmFamily.CLASSICAL, AlgorithmFamily.familyOf(algorithm));
        }
    }

    @Test
    public void everyAlgorithmValue_isCoveredByExactlyOneOfTheThreeListsAbove() {
        // The real tripwire: if a future algorithm is added to SaveKeyringParcel.Algorithm
        // without this test file being updated, it falls into neither list below and this
        // fails loudly -- rather than silently defaulting to CLASSICAL in familyOf's switch
        // (which would be flatly wrong if the new algorithm were, say, a second hash-based
        // scheme) and never being caught.
        Set<Algorithm> covered = new HashSet<>();
        covered.addAll(Arrays.asList(HASH_BASED_ALGORITHMS));
        covered.addAll(Arrays.asList(LATTICE_ALGORITHMS));
        covered.addAll(Arrays.asList(CLASSICAL_ALGORITHMS));

        for (Algorithm algorithm : Algorithm.values()) {
            assertTrue(algorithm + " is not covered by any family list in this test -- "
                            + "AlgorithmFamily.familyOf and this test both need updating",
                    covered.contains(algorithm));
        }
        assertEquals("the three lists together must have no overlap and match Algorithm.values() exactly",
                Algorithm.values().length, covered.size());
    }
}
