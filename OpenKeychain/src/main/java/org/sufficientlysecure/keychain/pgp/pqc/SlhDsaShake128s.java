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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;

/**
 * Standalone (non-composite) SLH-DSA-SHAKE-128s OpenPGP signing, implemented directly against
 * draft-ietf-openpgp-pqc-17 (the IETF OpenPGP WG's own git repo,
 * https://github.com/openpgp-pqc/draft-openpgp-pqc, tag draft-ietf-openpgp-pqc-17; see
 * docs/superpowers/specs/2026-07-07-pqc-migration-design.md for provenance). This is the
 * MAY-implement pure post-quantum signature algorithm of the draft (algorithm ID 32) --
 * architecturally distinct from every other PQC signing algorithm this codebase implements so
 * far ({@link CompositeMlDsa65Ed25519}, {@link CompositeMlDsa87Ed448}): there is no classical
 * component at all, no AND-combiner, no concatenated key/signature material. The public key,
 * secret key, and signature are exactly SLH-DSA's own native encodings, used unmodified.
 *
 * <p>This is hand-built wire-format logic, not inherited from Bouncy Castle: BC 1.84 has
 * SLH-DSA-SHAKE-128s *primitives* (used here, via {@code org.bouncycastle.crypto.params.SLHDSA*}
 * and {@code org.bouncycastle.crypto.{generators.SLHDSAKeyPairGenerator,signers.SLHDSASigner}} --
 * the current, non-deprecated surface, not the older {@code org.bouncycastle.pqc.crypto.slhdsa}
 * package) but no OpenPGP-packet-level support for this algorithm at all.
 *
 * <h3>Wire format (algorithm ID 32, per the draft's IANA and artifact-length tables)</h3>
 * <ul>
 *   <li>Public key material: the raw SLH-DSA-SHAKE-128s public key, 32 octets
 *       (PK.seed || PK.root, 16 octets each for this parameter set's {@code n = 16}).</li>
 *   <li>Secret key material: the raw SLH-DSA-SHAKE-128s secret key, 64 octets
 *       (SK.seed || SK.prf || PK.seed || PK.root per FIPS 205 -- this is BC's own {@code
 *       SLHDSAPrivateKeyParameters#getEncoded()} format, empirically confirmed to round-trip
 *       through {@code new SLHDSAPrivateKeyParameters(SLHDSAParameters, byte[])} and to
 *       recover the same public key via {@code getEncodedPublicKey()}; this is the *full*
 *       expanded secret key, not a compact seed the way ML-DSA/ML-KEM's composite secret
 *       material is -- FIPS 205 key generation has no seed-only compact form analogous to
 *       ML-DSA's {@code xi}/ML-KEM's {@code d||z}).</li>
 *   <li>Signature packet (type ID 2) v6 algorithm-specific data: the raw SLH-DSA-SHAKE-128s
 *       signature, 7856 octets, native encoding (not MPI-encoded) -- same convention as every
 *       other PQC signature algorithm in the draft.</li>
 * </ul>
 *
 * <h3>Signing input</h3>
 * <pre>
 *   dataDigest = the OpenPGP v6 signature "message digest" per RFC9580 §5.2.4, computed
 *                with the hash algorithm declared in the signature packet
 *   signature  = SLH-DSA.Sign(secretKey, dataDigest)
 * </pre>
 * The draft mandates a hash algorithm with a digest size of at least 256 bits for this
 * computation (identical wording and rationale to the composite ML-DSA + EdDSA case), and
 * states that a verifying implementation MUST reject any SLH-DSA signature using a smaller
 * digest; both {@link #sign} and {@link #verify} enforce this via {@link #MIN_DATA_DIGEST_LEN}.
 *
 * <p>Unlike {@link CompositeMlDsa65Ed25519}/{@link CompositeMlDsa87Ed448}, {@code
 * SLHDSASigner} implements BC's {@code MessageSigner} interface (message-at-once, no {@code
 * update()} streaming) -- {@link #sign} and {@link #verify} therefore take the already-computed
 * {@code dataDigest} directly as the "message" argument, rather than streaming it through an
 * incremental signer object. This class is stateless and thread-safe (unlike the streaming
 * composite classes' signer objects, which are constructed fresh per call anyway).
 */
public class SlhDsaShake128s {

    /**
     * Algorithm ID assigned by draft-ietf-openpgp-pqc-17 for standalone SLH-DSA-SHAKE-128s.
     * A MAY-implement algorithm per the draft; mirrors
     * {@code org.bouncycastle.bcpg.PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S}.
     */
    public static final int ALGORITHM_ID = 32;

    private static final SLHDSAParameters PARAMETERS = SLHDSAParameters.shake_128s;

    public static final int PUBLIC_KEY_LEN = 32;
    public static final int SECRET_KEY_LEN = 64;
    public static final int SIGNATURE_LEN = 7856;

    /**
     * The draft's mandated minimum digest size (256 bits = 32 octets) for the hash algorithm
     * used to compute the OpenPGP-level {@code dataDigest} fed to the SLH-DSA signer -- the
     * same floor and rationale as the composite ML-DSA + EdDSA case (see the class Javadoc).
     */
    public static final int MIN_DATA_DIGEST_LEN = 32;

    private SlhDsaShake128s() {
    }

    /** Key material: the raw public and (unencrypted) secret key bytes, native SLH-DSA encoding. */
    public static class KeyMaterial {
        public final byte[] publicKeyBytes;
        public final byte[] secretKeyBytes;

        KeyMaterial(byte[] publicKeyBytes, byte[] secretKeyBytes) {
            this.publicKeyBytes = publicKeyBytes;
            this.secretKeyBytes = secretKeyBytes;
        }
    }

    /**
     * Generates a fresh SLH-DSA-SHAKE-128s key pair, encoded exactly as the draft's public/
     * secret key material sections describe (the full native FIPS 205 secret key encoding,
     * not a compact seed -- see the class Javadoc for why this differs from ML-DSA/ML-KEM).
     */
    public static KeyMaterial generateKeyPair(SecureRandom random) {
        SLHDSAKeyPairGenerator keyPairGenerator = new SLHDSAKeyPairGenerator();
        keyPairGenerator.init(new SLHDSAKeyGenerationParameters(random, PARAMETERS));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        SLHDSAPrivateKeyParameters priv = (SLHDSAPrivateKeyParameters) keyPair.getPrivate();
        SLHDSAPublicKeyParameters pub = (SLHDSAPublicKeyParameters) keyPair.getPublic();

        byte[] publicKeyBytes = pub.getEncoded();
        byte[] secretKeyBytes = priv.getEncoded();

        if (publicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalStateException("unexpected public key length: " + publicKeyBytes.length);
        }
        if (secretKeyBytes.length != SECRET_KEY_LEN) {
            throw new IllegalStateException("unexpected secret key length: " + secretKeyBytes.length);
        }

        return new KeyMaterial(publicKeyBytes, secretKeyBytes);
    }

    /**
     * Signs an already-computed OpenPGP {@code dataDigest} (the v6 signature "message digest"
     * per RFC9580 §5.2.4, using the hash algorithm declared in the signature packet) with an
     * SLH-DSA-SHAKE-128s secret key, producing the raw signature bytes that go directly into
     * the signature packet's algorithm-specific field (native encoding, no MPI wrapping, no
     * classical component -- see class Javadoc).
     *
     * @param secretKeyBytes the SLH-DSA-SHAKE-128s secret key material (64 octets, full FIPS
     *        205 native encoding)
     * @param dataDigest the OpenPGP dataDigest to sign; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets (the draft's 256-bit digest-size floor)
     * @param random source of randomness passed to the underlying signer (FIPS 205's optional
     *        randomized signing); empirically confirmed BC's {@code SLHDSASigner} also accepts
     *        a plain (non-randomized) key parameter and produces a valid, deterministic
     *        signature either way, but this class always supplies one for defense in depth
     * @throws IllegalArgumentException if either input has the wrong length
     */
    public static byte[] sign(byte[] secretKeyBytes, byte[] dataDigest, SecureRandom random) {
        if (secretKeyBytes.length != SECRET_KEY_LEN) {
            throw new IllegalArgumentException("bad SLH-DSA-SHAKE-128s secret key length: "
                    + secretKeyBytes.length);
        }
        requireAdequateDigestSize(dataDigest);

        SLHDSAPrivateKeyParameters priv = new SLHDSAPrivateKeyParameters(PARAMETERS, secretKeyBytes);
        SLHDSASigner signer = new SLHDSASigner();
        signer.init(true, new ParametersWithRandom(priv, random));
        byte[] signature = signer.generateSignature(dataDigest);

        if (signature.length != SIGNATURE_LEN) {
            throw new IllegalStateException("unexpected SLH-DSA-SHAKE-128s signature length: "
                    + signature.length);
        }

        return signature;
    }

    /**
     * Verifies an SLH-DSA-SHAKE-128s signature over an already-computed OpenPGP {@code
     * dataDigest}.
     *
     * @param publicKeyBytes the SLH-DSA-SHAKE-128s public key material (32 octets)
     * @param dataDigest the OpenPGP dataDigest that was signed; MUST be at least
     *        {@link #MIN_DATA_DIGEST_LEN} octets (the draft's 256-bit digest-size floor) --
     *        a shorter digest is rejected outright, per the draft's MUST-reject requirement
     * @param signatureBytes the SLH-DSA-SHAKE-128s signature bytes (7856 octets), exactly as
     *        read off the wire
     * @throws IllegalArgumentException if either key/signature input has the wrong length
     */
    public static boolean verify(byte[] publicKeyBytes, byte[] dataDigest, byte[] signatureBytes) {
        if (publicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("bad SLH-DSA-SHAKE-128s public key length: "
                    + publicKeyBytes.length);
        }
        if (signatureBytes.length != SIGNATURE_LEN) {
            throw new IllegalArgumentException("bad SLH-DSA-SHAKE-128s signature length: "
                    + signatureBytes.length);
        }
        if (dataDigest.length < MIN_DATA_DIGEST_LEN) {
            // Per the draft: "A verifying implementation MUST reject any SLH-DSA signature
            // that uses a hash algorithm with a smaller digest size."
            return false;
        }

        SLHDSAPublicKeyParameters pub = new SLHDSAPublicKeyParameters(PARAMETERS, publicKeyBytes);
        SLHDSASigner verifier = new SLHDSASigner();
        verifier.init(false, pub);
        return verifier.verifySignature(dataDigest, signatureBytes);
    }

    private static void requireAdequateDigestSize(byte[] dataDigest) {
        if (dataDigest.length < MIN_DATA_DIGEST_LEN) {
            throw new IllegalArgumentException("dataDigest too short for SLH-DSA-SHAKE-128s "
                    + "signing: " + dataDigest.length + " octets, need at least "
                    + MIN_DATA_DIGEST_LEN + " (the draft's 256-bit digest-size floor)");
        }
    }
}
