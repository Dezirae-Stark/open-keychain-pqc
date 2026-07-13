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

import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;

/**
 * Which underlying hard mathematical problem an algorithm's security rests on. Distinct from
 * {@code SaveKeyringParcel.isNonStandardClosedEcosystemPqc} (composite vs. standalone) and
 * {@code SaveKeyringParcel.canSign}/{@code canEncrypt} (capability) -- this classification exists
 * so a signing-capable subkey set can be checked for structural hedge-diversity: relying entirely
 * on one family means a single future cryptanalytic break against that family's hard problem
 * (lattice problems for ML-KEM/ML-DSA, or a hash-function break for SLH-DSA) is correlated risk
 * across every signing subkey a user has, the same way a monoculture crop is vulnerable to one
 * pathogen. No such classification existed anywhere in this codebase before -- see
 * docs/superpowers/ideation/2026-07-13-feature-divergence.md's "algorithm-diversity" idea and its
 * Phase 5 triage.
 */
public enum AlgorithmFamily {
    /** ML-KEM and ML-DSA (both composite and standalone): security rests on lattice problems. */
    LATTICE,
    /** SLH-DSA: security rests on the underlying hash function's collision/preimage resistance,
     *  a structurally different hard problem than lattice-based schemes. */
    HASH_BASED,
    /** RSA, DSA, ElGamal, and every elliptic-curve algorithm (ECDSA/ECDH/EdDSA, and the classical
     *  component of every composite PQC algorithm): security rests on integer factorization or
     *  the discrete log problem (finite-field or elliptic-curve). Not itself post-quantum-safe,
     *  but tracked here because a composite algorithm's classical component is a real structural
     *  ingredient of that algorithm's overall hedge, not just dead weight. */
    CLASSICAL;

    /**
     * The family {@code algorithm}'s security rests on. Composite algorithms (which combine a
     * classical and a PQC component) are classified by their PQC component, since that's the
     * post-quantum-relevant classification -- the classical component is always {@link
     * #CLASSICAL} and is not separately exposed by this method (a composite algorithm's classical
     * ingredient isn't a separately-selectable subkey in this codebase, so there's no call site
     * that needs it split out).
     */
    public static AlgorithmFamily familyOf(Algorithm algorithm) {
        switch (algorithm) {
            case SLH_DSA_SHAKE_128S:
                return HASH_BASED;
            case ML_KEM_768_X25519:
            case ML_KEM_1024_X448:
            case ML_DSA_65_ED25519:
            case ML_DSA_87_ED448:
            case STANDALONE_ML_KEM_768:
            case STANDALONE_ML_KEM_1024:
            case STANDALONE_ML_DSA_65:
            case STANDALONE_ML_DSA_87:
                return LATTICE;
            default:
                // RSA, DSA, ELGAMAL, ECDSA, ECDH, EDDSA
                return CLASSICAL;
        }
    }
}
