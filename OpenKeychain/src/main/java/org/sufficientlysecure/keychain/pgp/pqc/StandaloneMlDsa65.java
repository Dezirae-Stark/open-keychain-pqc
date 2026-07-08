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
 * Standalone (non-composite, closed-ecosystem) ML-DSA-65 OpenPGP signing -- OpenKeychain
 * private-use algorithm ID 102 ({@code EXPERIMENTAL_3}), deliberately <b>not</b> defined by
 * draft-ietf-openpgp-pqc-17 or any other spec (the draft only defines composite ML-DSA-65
 * combined with Ed25519, algorithm ID 30, see {@link CompositeMlDsa65Ed25519}). See
 * docs/superpowers/specs/2026-07-07-pqc-migration-design.md (Standalone/Closed-Ecosystem Mode
 * section) for the design that motivates this and the full rationale for the wire format below.
 *
 * <p>Architecturally this is a straightforward simplification of {@link
 * CompositeMlDsa65Ed25519}: the same BC ML-DSA-65 primitive calls
 * ({@code org.bouncycastle.crypto.params.MLDSA*}, {@code org.bouncycastle.crypto.signers.MLDSASigner})
 * and the same seed-format secret-key convention, with the Ed25519 half and the AND-combiner
 * removed entirely -- there is no classical component at all, exactly like {@link
 * SlhDsaShake128s} is to the composite ML-DSA classes for its own (SLH-DSA) primitive. Unlike
 * {@link SlhDsaShake128s}, though, {@code MLDSASigner} implements BC's streaming {@code Signer}
 * interface (an {@code update()} method), not the message-at-once {@code MessageSigner}
 * interface -- so {@link #sign}/{@link #verify} here mirror {@link CompositeMlDsa65Ed25519}'s
 * streaming style, not {@link SlhDsaShake128s}'s.
 *
 * <h3>Wire format (algorithm ID 102, OpenKeychain private-use assignment)</h3>
 * <ul>
 *   <li>Public key material: the raw ML-DSA-65 public key, 1952 octets, no concatenation.</li>
 *   <li>Secret key material: the raw ML-DSA-65 secret key in <em>seed format</em>, 32 octets
 *       ({@code xi} per FIPS 204 §3.6.3 / step 1 of {@code ML-DSA.KeyGen}), expanded via
 *       {@code ML-DSA.KeyGen_internal} only at point of use, never stored expanded -- same
 *       convention as every other ML-DSA case in this codebase.</li>
 *   <li>Signature packet (type ID 2) v6 algorithm-specific data: the raw ML-DSA-65 signature,
 *       3309 octets, native encoding (not MPI-encoded), no concatenation.</li>
 * </ul>
 *
 * <h3>Signing input</h3>
 * <pre>
 *   dataDigest = the OpenPGP v6 signature "message digest" per RFC9580 §5.2.4, computed
 *                with the hash algorithm declared in the signature packet
 *   signature  = ML-DSA.Sign(secretKey, dataDigest)
 * </pre>
 *
 * <h3>256-bit minimum-digest floor: kept, as our own hygiene decision</h3>
 * The composite classes ({@link CompositeMlDsa65Ed25519}, {@link CompositeMlDsa87Ed448}) enforce
 * a 256-bit minimum digest size because draft-ietf-openpgp-pqc-17 explicitly mandates it for
 * the composite construction. No such external mandate exists for this private-use, standalone
 * algorithm -- but the floor is enforced here anyway ({@link #MIN_DATA_DIGEST_LEN}), as this
 * codebase's own hygiene decision: FIPS 204's own security categories (3 here, 5 for
 * ML-DSA-87) are a claim about the strength of the ML-DSA math itself, and that claim is
 * undermined by a weak *outer* hash regardless of whether a classical co-signer's own
 * collision-resistance argument happens to be riding on the same digest. The composite case's
 * rationale for the floor was never really "because a classical co-signer is present" in the
 * first place -- it was "the digest is the only thing standing between a signature and a
 * second-preimage/forgery on the message actually signed" -- and that reasoning applies
 * identically with zero classical components. Relaxing the floor here, absent any external
 * requirement forcing us to, would be a weaker posture for no compensating benefit.
 */
public class StandaloneMlDsa65 {

    /**
     * Algorithm ID assigned by this codebase (private-use, {@code EXPERIMENTAL_3}) for
     * standalone ML-DSA-65 signing. NOT IANA-registered, NOT defined by
     * draft-ietf-openpgp-pqc-17 -- see the class Javadoc.
     */
    public static final int ALGORITHM_ID = 102;

    private static final MLDSAParameters PARAMETERS = MLDSAParameters.ml_dsa_65;

    public static final int PUBLIC_KEY_LEN = 1952;
    public static final int SECRET_KEY_LEN = 32; // seed (xi), FIPS 204 §3.6.3
    public static final int SIGNATURE_LEN = 3309;

    /**
     * The 256-bit minimum digest-size floor this codebase enforces for standalone ML-DSA-65
     * signing, as its own hygiene decision -- see the class Javadoc for why this is kept even
     * though no external spec mandates it for this private-use algorithm.
     */
    public static final int MIN_DATA_DIGEST_LEN = 32;

    private StandaloneMlDsa65() {
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
     * Generates a fresh standalone ML-DSA-65 key pair, secret material kept in the 32-octet
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
     * Signs an already-computed OpenPGP {@code dataDigest} (the v6 signature "message digest"
     * per RFC9580 §5.2.4, using the hash algorithm declared in the signature packet) with a
     * standalone ML-DSA-65 secret key, producing the raw signature bytes that go directly into
     * the signature packet's algorithm-specific field (native encoding, no MPI wrapping, no
     * classical component -- see class Javadoc).
     *
     * @param secretKeyBytes the ML-DSA-65 secret key material (32-octet seed format)
     * @param dataDigest the OpenPGP dataDigest to sign; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets
     * @param random source of randomness for ML-DSA's hedged (randomized) signing
     * @throws IllegalArgumentException if either input has the wrong length
     * @throws IllegalStateException if the underlying BC signer refuses to produce a signature
     */
    public static byte[] sign(byte[] secretKeyBytes, byte[] dataDigest, SecureRandom random) {
        if (secretKeyBytes.length != SECRET_KEY_LEN) {
            throw new IllegalArgumentException("bad standalone ML-DSA-65 secret key length: "
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
            throw new IllegalStateException("standalone ML-DSA-65 signature generation failed", e);
        }

        if (signature.length != SIGNATURE_LEN) {
            throw new IllegalStateException("unexpected ML-DSA-65 signature length: " + signature.length);
        }

        return signature;
    }

    /**
     * Verifies a standalone ML-DSA-65 signature over an already-computed OpenPGP {@code
     * dataDigest}.
     *
     * @param publicKeyBytes the ML-DSA-65 public key material (1952 octets)
     * @param dataDigest the OpenPGP dataDigest that was signed; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets -- a shorter digest is rejected outright, per
     *        this codebase's own hygiene floor (see class Javadoc)
     * @param signatureBytes the ML-DSA-65 signature bytes (3309 octets), exactly as read off
     *        the wire
     * @throws IllegalArgumentException if either key/signature input has the wrong length
     */
    public static boolean verify(byte[] publicKeyBytes, byte[] dataDigest, byte[] signatureBytes) {
        if (publicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("bad standalone ML-DSA-65 public key length: "
                    + publicKeyBytes.length);
        }
        if (signatureBytes.length != SIGNATURE_LEN) {
            throw new IllegalArgumentException("bad standalone ML-DSA-65 signature length: "
                    + signatureBytes.length);
        }
        if (dataDigest.length < MIN_DATA_DIGEST_LEN) {
            // This codebase's own hygiene floor -- see class Javadoc.
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
            throw new IllegalArgumentException("dataDigest too short for standalone ML-DSA-65 "
                    + "signing: " + dataDigest.length + " octets, need at least "
                    + MIN_DATA_DIGEST_LEN + " (this codebase's own 256-bit digest-size floor)");
        }
    }
}
