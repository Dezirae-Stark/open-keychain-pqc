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

package org.sufficientlysecure.keychain.pgp.pqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;

/**
 * Standalone (non-composite, closed-ecosystem) ML-DSA-87 OpenPGP signing -- OpenKeychain
 * private-use algorithm ID 103 ({@code EXPERIMENTAL_4}), deliberately <b>not</b> defined by
 * draft-ietf-openpgp-pqc-17 or any other spec (the draft only defines composite ML-DSA-87
 * combined with Ed448, algorithm ID 31, see {@link CompositeMlDsa87Ed448}). Mirrors {@link
 * StandaloneMlDsa65} exactly -- see that class's Javadoc for the full rationale (architecture,
 * wire-format conventions, and why the 256-bit minimum-digest floor is kept here as this
 * codebase's own hygiene decision, applying identically at ML-DSA-87's higher category 5) --
 * this is simply the higher-security-category sibling, same as {@link CompositeMlDsa87Ed448} is
 * to {@link CompositeMlDsa65Ed25519} for the composite case.
 *
 * <h3>Wire format (algorithm ID 103, OpenKeychain private-use assignment)</h3>
 * <ul>
 *   <li>Public key material: the raw ML-DSA-87 public key, 2592 octets, no concatenation.</li>
 *   <li>Secret key material: the raw ML-DSA-87 secret key in seed format, 32 octets ({@code xi}
 *       per FIPS 204 §3.6.3), expanded via {@code ML-DSA.KeyGen_internal} only at point of use.</li>
 *   <li>Signature packet (type ID 2) v6 algorithm-specific data: the raw ML-DSA-87 signature,
 *       4627 octets, native encoding (not MPI-encoded), no concatenation.</li>
 * </ul>
 */
public class StandaloneMlDsa87 {

    /**
     * Algorithm ID assigned by this codebase (private-use, {@code EXPERIMENTAL_4}) for
     * standalone ML-DSA-87 signing. NOT IANA-registered, NOT defined by
     * draft-ietf-openpgp-pqc-17 -- see the class Javadoc.
     */
    public static final int ALGORITHM_ID = 103;

    private static final MLDSAParameters PARAMETERS = MLDSAParameters.ml_dsa_87;

    public static final int PUBLIC_KEY_LEN = 2592;
    public static final int SECRET_KEY_LEN = 32; // seed (xi), FIPS 204 §3.6.3
    public static final int SIGNATURE_LEN = 4627;

    /**
     * The 256-bit minimum digest-size floor this codebase enforces for standalone ML-DSA-87
     * signing, as its own hygiene decision -- see {@link StandaloneMlDsa65}'s Javadoc for why
     * this is kept even though no external spec mandates it for this private-use algorithm.
     */
    public static final int MIN_DATA_DIGEST_LEN = 32;

    private StandaloneMlDsa87() {
    }

    /** Key material: the raw public and (unencrypted, seed-format) secret key bytes. */
    public static class KeyMaterial {
        public final byte[] publicKeyBytes;
        public final byte[] secretKeyBytes;

        KeyMaterial(byte[] publicKeyBytes, byte[] secretKeyBytes) {
            this.publicKeyBytes = publicKeyBytes;
            this.secretKeyBytes = secretKeyBytes;
        }
    }

    /**
     * Generates a fresh standalone ML-DSA-87 key pair, secret material kept in the 32-octet
     * seed format {@code xi} (FIPS 204 §3.6.3), not the expanded form.
     */
    public static KeyMaterial generateKeyPair(SecureRandom random) {
        byte[] seed = new byte[SECRET_KEY_LEN];
        random.nextBytes(seed);
        MLDSAPrivateKeyParameters priv = new MLDSAPrivateKeyParameters(PARAMETERS, seed, null);
        MLDSAPublicKeyParameters pub = priv.getPublicKeyParameters();

        byte[] publicKeyBytes = pub.getEncoded();
        byte[] secretKeyBytes = seed;

        if (publicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalStateException("unexpected public key length: " + publicKeyBytes.length);
        }

        return new KeyMaterial(publicKeyBytes, secretKeyBytes);
    }

    /**
     * Builds a standalone ML-DSA-87 key pair deterministically from a caller-supplied seed,
     * instead of drawing fresh randomness -- used by raw PQC key material import (see
     * {@code RawPqcKeyImport}). Mirrors {@link StandaloneMlDsa65#generateKeyPairFromSeed}
     * exactly, with ML-DSA-87's own parameter set.
     *
     * @param seed ML-DSA-87 seed ({@code xi}), exactly {@code SECRET_KEY_LEN} (32) octets
     * @throws IllegalArgumentException if the seed has the wrong length
     */
    public static KeyMaterial generateKeyPairFromSeed(byte[] seed) {
        if (seed.length != SECRET_KEY_LEN) {
            throw new IllegalArgumentException(
                    "bad ML-DSA-87 seed length: " + seed.length + ", expected " + SECRET_KEY_LEN);
        }

        MLDSAPrivateKeyParameters priv = new MLDSAPrivateKeyParameters(PARAMETERS, seed, null);
        MLDSAPublicKeyParameters pub = priv.getPublicKeyParameters();

        byte[] publicKeyBytes = pub.getEncoded();
        byte[] secretKeyBytes = seed.clone();

        if (publicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalStateException("unexpected public key length: " + publicKeyBytes.length);
        }

        return new KeyMaterial(publicKeyBytes, secretKeyBytes);
    }

    /**
     * Signs an already-computed OpenPGP {@code dataDigest} with a standalone ML-DSA-87 secret
     * key, producing the raw signature bytes for the signature packet's algorithm-specific
     * field (native encoding, no MPI wrapping, no classical component -- see
     * {@link StandaloneMlDsa65}'s class Javadoc).
     *
     * @param secretKeyBytes the ML-DSA-87 secret key material (32-octet seed format)
     * @param dataDigest the OpenPGP dataDigest to sign; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets
     * @param random source of randomness for ML-DSA's hedged (randomized) signing
     * @throws IllegalArgumentException if either input has the wrong length
     * @throws IllegalStateException if the underlying BC signer refuses to produce a signature
     */
    public static byte[] sign(byte[] secretKeyBytes, byte[] dataDigest, SecureRandom random) {
        if (secretKeyBytes.length != SECRET_KEY_LEN) {
            throw new IllegalArgumentException("bad standalone ML-DSA-87 secret key length: "
                    + secretKeyBytes.length);
        }
        requireAdequateDigestSize(dataDigest);

        MLDSAPrivateKeyParameters priv = new MLDSAPrivateKeyParameters(PARAMETERS, secretKeyBytes, null);
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, new ParametersWithRandom(priv, random));
        signer.update(dataDigest, 0, dataDigest.length);
        byte[] signature;
        try {
            signature = signer.generateSignature();
        } catch (CryptoException e) {
            throw new IllegalStateException("standalone ML-DSA-87 signature generation failed", e);
        }

        if (signature.length != SIGNATURE_LEN) {
            throw new IllegalStateException("unexpected ML-DSA-87 signature length: " + signature.length);
        }

        return signature;
    }

    /**
     * Verifies a standalone ML-DSA-87 signature over an already-computed OpenPGP {@code
     * dataDigest}.
     *
     * @param publicKeyBytes the ML-DSA-87 public key material (2592 octets)
     * @param dataDigest the OpenPGP dataDigest that was signed; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets -- a shorter digest is rejected outright, per
     *        this codebase's own hygiene floor
     * @param signatureBytes the ML-DSA-87 signature bytes (4627 octets), exactly as read off
     *        the wire
     * @throws IllegalArgumentException if either key/signature input has the wrong length
     */
    public static boolean verify(byte[] publicKeyBytes, byte[] dataDigest, byte[] signatureBytes) {
        if (publicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("bad standalone ML-DSA-87 public key length: "
                    + publicKeyBytes.length);
        }
        if (signatureBytes.length != SIGNATURE_LEN) {
            throw new IllegalArgumentException("bad standalone ML-DSA-87 signature length: "
                    + signatureBytes.length);
        }
        if (dataDigest.length < MIN_DATA_DIGEST_LEN) {
            // This codebase's own hygiene floor -- see StandaloneMlDsa65's class Javadoc.
            return false;
        }

        MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(PARAMETERS, publicKeyBytes);
        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, pub);
        verifier.update(dataDigest, 0, dataDigest.length);
        return verifier.verifySignature(signatureBytes);
    }

    private static void requireAdequateDigestSize(byte[] dataDigest) {
        if (dataDigest.length < MIN_DATA_DIGEST_LEN) {
            throw new IllegalArgumentException("dataDigest too short for standalone ML-DSA-87 "
                    + "signing: " + dataDigest.length + " octets, need at least "
                    + MIN_DATA_DIGEST_LEN + " (this codebase's own 256-bit digest-size floor)");
        }
    }
}
