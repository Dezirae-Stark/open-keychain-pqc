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
import java.util.Arrays;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.MLDSASigner;

/**
 * Composite ML-DSA-87/Ed448 OpenPGP signing, implemented directly against
 * draft-ietf-openpgp-pqc-17 (the IETF OpenPGP WG's own git repo,
 * https://github.com/openpgp-pqc/draft-openpgp-pqc, tag draft-ietf-openpgp-pqc-17;
 * datatracker/ietf.org text renderings are not reachable from this build environment,
 * see docs/superpowers/specs/2026-07-07-pqc-migration-design.md for provenance). This is the
 * SHOULD-implement composite signature algorithm of the draft (algorithm ID 31) -- the
 * higher-security-category sibling of the MUST-implement ML-DSA-65+Ed25519 (algorithm ID 30,
 * see {@link CompositeMlDsa65Ed25519}), which this class mirrors structurally.
 *
 * <p>This is hand-built wire-format logic, not inherited from Bouncy Castle: BC 1.84 has
 * ML-DSA-87/Ed448 *primitives* (used here, via {@code org.bouncycastle.crypto.params.MLDSA*}
 * and {@code org.bouncycastle.crypto.signers.{MLDSASigner,Ed448Signer}} -- the current,
 * non-deprecated surface, not the older {@code org.bouncycastle.pqc.crypto.mldsa} package) but
 * no OpenPGP-packet-level composite signature support at all, exactly as already established
 * for {@link CompositeMlDsa65Ed25519} and {@link CompositeMlKem768X25519}.
 *
 * <p>One API difference from the Ed25519 case: {@link Ed448Signer}'s constructor takes an
 * explicit {@code context} byte array (RFC 8032's Ed448 context string), unlike {@code
 * Ed25519Signer}'s no-arg constructor. This class always passes an empty context ({@code new
 * byte[0]}), matching the draft's signing steps below (which specify no context string for
 * either component signature).
 *
 * <h3>Wire format (algorithm ID 31, per the draft's IANA table)</h3>
 * <ul>
 *   <li>Public key material (fixed-length octet strings, concatenated, classical component
 *       first): Ed448 public key (57 octets) || ML-DSA-87 public key (2592 octets).</li>
 *   <li>Secret key material (same classical-first order): Ed448 secret key (57 octets) ||
 *       ML-DSA-87 secret key in <em>seed format</em> (32 octets, {@code xi} per FIPS 204
 *       §3.6.3 / step 1 of {@code ML-DSA.KeyGen} -- 32 octets regardless of parameter set),
 *       expanded via {@code ML-DSA.KeyGen_internal} only at point of use, never stored
 *       expanded.</li>
 *   <li>Signature packet (type ID 2) v6 algorithm-specific data: Ed448 signature (114
 *       octets) || ML-DSA-87 signature (4627 octets) = 4741 octets total, again
 *       classical-first, raw/native encoding (not MPI-encoded) -- exactly like the existing
 *       Ed25519/Ed448 (algorithm IDs 27/28) native signature encoding this pinned BC release
 *       already supports for the classical-only case.</li>
 * </ul>
 *
 * <h3>Signing input (draft's algorithm-specific signing steps, verbatim in spirit)</h3>
 * <pre>
 *   dataDigest = the OpenPGP v6 signature "message digest" per RFC9580 §5.2.4, computed
 *                with the hash algorithm declared in the signature packet
 *   EdDSA signature  = EdDSA.Sign(eddsaSecretKey, dataDigest)
 *   ML-DSA signature = ML-DSA.Sign(mldsaSecretKey, dataDigest)
 * </pre>
 * The draft mandates a hash algorithm with a digest size of at least 256 bits for this
 * computation, and states that a verifying implementation MUST reject any composite
 * signature using a smaller digest; both {@link #sign} and {@link #verify} enforce this via
 * {@link #MIN_DATA_DIGEST_LEN}. There is no separate/different hash exposed as configurable
 * for ML-DSA's own internal Fiat-Shamir transform -- {@code ML-DSA.Sign}/{@code ML-DSA.Verify}
 * are invoked per FIPS-204 defaults (hedged, empty context string), whose internal SHAKE-256
 * hashing is fixed by the algorithm and unrelated to the outer OpenPGP hash-algorithm octet.
 *
 * <p>Verification requires <em>both</em> component signatures to verify (an AND-combiner);
 * this mirrors every other composite OpenPGP-PQC signature/KEM combiner in the draft, which
 * are all constructed so that breaking the composite requires breaking every component.
 */
public class CompositeMlDsa87Ed448 {

    /**
     * Algorithm ID assigned by draft-ietf-openpgp-pqc-17 for composite ML-DSA-87+Ed448.
     * A SHOULD-implement algorithm per the draft; mirrors
     * {@code org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ML_DSA_87_Ed448}.
     */
    public static final int ALGORITHM_ID = 31;

    private static final int ED448_LEN = 57;
    private static final int ED448_SIG_LEN = 114;
    private static final int MLDSA_87_PUB_LEN = 2592;
    private static final int MLDSA_87_SEED_LEN = 32;
    private static final int MLDSA_87_SIG_LEN = 4627;

    /** RFC 8032 Ed448 context string used for both component signatures: always empty. */
    private static final byte[] ED448_CONTEXT = new byte[0];

    public static final int COMPOSITE_PUBLIC_KEY_LEN = ED448_LEN + MLDSA_87_PUB_LEN; // 2649
    public static final int COMPOSITE_SECRET_KEY_LEN = ED448_LEN + MLDSA_87_SEED_LEN; // 89
    public static final int COMPOSITE_SIGNATURE_LEN = ED448_SIG_LEN + MLDSA_87_SIG_LEN; // 4741

    /**
     * The draft's mandated minimum digest size (256 bits = 32 octets) for the hash algorithm
     * used to compute the OpenPGP-level {@code dataDigest} fed to both component signers.
     * Both {@link #sign} and {@link #verify} enforce this -- see the class Javadoc.
     */
    public static final int MIN_DATA_DIGEST_LEN = 32;

    private CompositeMlDsa87Ed448() {
    }

    /** Composite key material: concatenated public and (unencrypted) secret key bytes. */
    public static class KeyMaterial {
        public final byte[] publicKeyBytes;
        public final byte[] secretKeyBytes;

        KeyMaterial(byte[] publicKeyBytes, byte[] secretKeyBytes) {
            this.publicKeyBytes = publicKeyBytes;
            this.secretKeyBytes = secretKeyBytes;
        }
    }

    /**
     * Generates a fresh composite ML-DSA-87/Ed448 key pair, encoded exactly as the draft's
     * public/secret key material sections describe (ML-DSA secret material kept in the
     * 32-octet seed format {@code xi}, per FIPS 204 §3.6.3, not the expanded form).
     */
    public static KeyMaterial generateKeyPair(SecureRandom random) {
        Ed448PrivateKeyParameters edPriv = new Ed448PrivateKeyParameters(random);
        Ed448PublicKeyParameters edPub = edPriv.generatePublicKey();

        byte[] seed = new byte[MLDSA_87_SEED_LEN];
        random.nextBytes(seed);
        MLDSAPrivateKeyParameters mldsaPriv =
                new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, seed, null);
        MLDSAPublicKeyParameters mldsaPub = mldsaPriv.getPublicKeyParameters();

        byte[] publicKeyBytes = concat(edPub.getEncoded(), mldsaPub.getEncoded());
        byte[] secretKeyBytes = concat(edPriv.getEncoded(), seed);

        if (publicKeyBytes.length != COMPOSITE_PUBLIC_KEY_LEN) {
            throw new IllegalStateException("unexpected composite public key length: " + publicKeyBytes.length);
        }
        if (secretKeyBytes.length != COMPOSITE_SECRET_KEY_LEN) {
            throw new IllegalStateException("unexpected composite secret key length: " + secretKeyBytes.length);
        }

        return new KeyMaterial(publicKeyBytes, secretKeyBytes);
    }

    /**
     * Signs an already-computed OpenPGP {@code dataDigest} (the v6 signature "message digest"
     * per RFC9580 §5.2.4, using the hash algorithm declared in the signature packet) with a
     * composite ML-DSA-87/Ed448 secret key, producing the raw {@code
     * eddsaSignature || mldsaSignature} bytes that go directly into the signature packet's
     * algorithm-specific field (native encoding, no MPI wrapping -- see class Javadoc).
     *
     * @param compositeSecretKeyBytes the composite secret key material (89 octets:
     *        Ed448 secret key || ML-DSA-87 seed)
     * @param dataDigest the OpenPGP dataDigest to sign; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets (the draft's 256-bit digest-size floor)
     * @param random source of randomness for ML-DSA's hedged (randomized) signing
     * @throws IllegalArgumentException if either input has the wrong length
     * @throws IllegalStateException if the underlying BC signer refuses to produce a signature
     */
    public static byte[] sign(byte[] compositeSecretKeyBytes, byte[] dataDigest, SecureRandom random) {
        if (compositeSecretKeyBytes.length != COMPOSITE_SECRET_KEY_LEN) {
            throw new IllegalArgumentException("bad composite secret key length: "
                    + compositeSecretKeyBytes.length);
        }
        requireAdequateDigestSize(dataDigest);

        byte[] edSecBytes = slice(compositeSecretKeyBytes, 0, ED448_LEN);
        byte[] mldsaSeed = slice(compositeSecretKeyBytes, ED448_LEN, MLDSA_87_SEED_LEN);

        Ed448PrivateKeyParameters edPriv = new Ed448PrivateKeyParameters(edSecBytes);
        Ed448Signer edSigner = new Ed448Signer(ED448_CONTEXT);
        edSigner.init(true, edPriv);
        edSigner.update(dataDigest, 0, dataDigest.length);
        byte[] edSignature = edSigner.generateSignature();

        MLDSAPrivateKeyParameters mldsaPriv =
                new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, mldsaSeed, null);
        MLDSASigner mldsaSigner = new MLDSASigner();
        mldsaSigner.init(true, new ParametersWithRandom(mldsaPriv, random));
        mldsaSigner.update(dataDigest, 0, dataDigest.length);
        byte[] mldsaSignature;
        try {
            mldsaSignature = mldsaSigner.generateSignature();
        } catch (CryptoException e) {
            throw new IllegalStateException("ML-DSA-87 signature generation failed", e);
        }

        if (edSignature.length != ED448_SIG_LEN) {
            throw new IllegalStateException("unexpected Ed448 signature length: " + edSignature.length);
        }
        if (mldsaSignature.length != MLDSA_87_SIG_LEN) {
            throw new IllegalStateException("unexpected ML-DSA-87 signature length: " + mldsaSignature.length);
        }

        return concat(edSignature, mldsaSignature);
    }

    /**
     * Verifies a composite ML-DSA-87/Ed448 signature over an already-computed OpenPGP
     * {@code dataDigest}. Both component signatures must independently verify (AND-combiner,
     * per the class Javadoc) for this to return {@code true}.
     *
     * @param compositePublicKeyBytes the composite public key material (2649 octets:
     *        Ed448 public key || ML-DSA-87 public key)
     * @param dataDigest the OpenPGP dataDigest that was signed; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets (the draft's 256-bit digest-size floor) --
     *        a shorter digest is rejected outright, per the draft's MUST-reject requirement
     * @param signatureBytes the composite signature bytes (4741 octets: Ed448 signature ||
     *        ML-DSA-87 signature), exactly as read off the wire
     * @throws IllegalArgumentException if any input has the wrong length
     */
    public static boolean verify(byte[] compositePublicKeyBytes, byte[] dataDigest, byte[] signatureBytes) {
        if (compositePublicKeyBytes.length != COMPOSITE_PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("bad composite public key length: "
                    + compositePublicKeyBytes.length);
        }
        if (signatureBytes.length != COMPOSITE_SIGNATURE_LEN) {
            throw new IllegalArgumentException("bad composite signature length: "
                    + signatureBytes.length);
        }
        if (dataDigest.length < MIN_DATA_DIGEST_LEN) {
            // Per the draft: "A verifying implementation MUST reject any composite ML-DSA +
            // EdDSA signature that uses a hash algorithm with a smaller digest size."
            return false;
        }

        byte[] edPubBytes = slice(compositePublicKeyBytes, 0, ED448_LEN);
        byte[] mldsaPubBytes = slice(compositePublicKeyBytes, ED448_LEN, MLDSA_87_PUB_LEN);
        byte[] edSignature = slice(signatureBytes, 0, ED448_SIG_LEN);
        byte[] mldsaSignature = slice(signatureBytes, ED448_SIG_LEN, MLDSA_87_SIG_LEN);

        Ed448PublicKeyParameters edPub = new Ed448PublicKeyParameters(edPubBytes);
        Ed448Signer edVerifier = new Ed448Signer(ED448_CONTEXT);
        edVerifier.init(false, edPub);
        edVerifier.update(dataDigest, 0, dataDigest.length);
        boolean edOk = edVerifier.verifySignature(edSignature);

        MLDSAPublicKeyParameters mldsaPub =
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, mldsaPubBytes);
        MLDSASigner mldsaVerifier = new MLDSASigner();
        mldsaVerifier.init(false, mldsaPub);
        mldsaVerifier.update(dataDigest, 0, dataDigest.length);
        boolean mldsaOk = mldsaVerifier.verifySignature(mldsaSignature);

        // AND-combiner: the composite signature is only valid if *both* components are.
        return edOk && mldsaOk;
    }

    private static void requireAdequateDigestSize(byte[] dataDigest) {
        if (dataDigest.length < MIN_DATA_DIGEST_LEN) {
            throw new IllegalArgumentException("dataDigest too short for composite ML-DSA + EdDSA "
                    + "signing: " + dataDigest.length + " octets, need at least "
                    + MIN_DATA_DIGEST_LEN + " (the draft's 256-bit digest-size floor)");
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] slice(byte[] a, int off, int len) {
        return Arrays.copyOfRange(a, off, off + len);
    }
}
