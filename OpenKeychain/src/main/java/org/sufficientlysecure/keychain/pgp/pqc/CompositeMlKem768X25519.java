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

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * Composite ML-KEM-768/X25519 OpenPGP encryption, implemented directly against
 * draft-ietf-openpgp-pqc-17 (the IETF OpenPGP WG's own git repo,
 * https://github.com/openpgp-pqc/draft-openpgp-pqc, tag draft-ietf-openpgp-pqc-17;
 * datatracker/ietf.org text renderings are not reachable from this build environment,
 * see docs/superpowers/specs/2026-07-07-pqc-migration-design.md for provenance).
 *
 * <p>This is hand-built wire-format logic, not inherited from Bouncy Castle: BC 1.84 has
 * ML-KEM/X25519 *primitives* (used here) but no OpenPGP-packet-level composite KEM support
 * at all (no {@code Composite*}/{@code MLKEM*} classes in {@code org.bouncycastle.bcpg} or
 * {@code org.bouncycastle.openpgp}). See the project's recorded finding
 * ({@code pqc_migration_no_upstream_bc_support} memory note) for how this was confirmed.
 *
 * <h3>Wire format (algorithm ID 35, per the draft's IANA table)</h3>
 * <ul>
 *   <li>Public key material (fixed-length octet strings, concatenated):
 *       X25519 public key (32 octets) || ML-KEM-768 public key (1184 octets).</li>
 *   <li>Secret key material: X25519 secret key (32 octets) || ML-KEM-768 secret key in
 *       <em>seed format</em> (64 octets, {@code d || z} per FIPS 203 §3.3), expanded via
 *       {@code ML-KEM.KeyGen_internal} only at point of use, never stored expanded.</li>
 *   <li>PKESK (Public-Key Encrypted Session Key, packet type 1) v3 algorithm-specific data:
 *       {@code ecdhCipherText (32) || mlkemCipherText (1088) || len(C,symAlgId) (1) ||
 *       symAlgId (1, v3 only, plaintext) || C}, where {@code C} is the RFC 3394 AES-256
 *       key-wrap of the raw content-encryption session key (no symAlgId/checksum framing
 *       inside {@code C} itself -- that framing is classical-PGP-only and does not apply to
 *       RFC 3394's own built-in 64-bit integrity check).</li>
 * </ul>
 *
 * <h3>Key combiner ("Key Combiner" section of the draft, verbatim)</h3>
 * <pre>
 *   KEK = SHA3-256(
 *             mlkemKeyShare || ecdhKeyShare ||
 *             ecdhCipherText || ecdhPublicKey ||
 *             algId || domSep || len(domSep)
 *         )
 * </pre>
 * where {@code domSep} is the UTF-8 string {@code "OpenPGPCompositeKDFv1"} (21 octets) and
 * {@code ecdhPublicKey} is the recipient's static X25519 public key. This is stated by the
 * draft to be compliant with the QSF/X-Wing construction ({@code BCD+24}).
 */
public class CompositeMlKem768X25519 {

    /**
     * Algorithm ID assigned by draft-ietf-openpgp-pqc-17 for composite ML-KEM-768+X25519.
     * A MUST-implement algorithm per the draft; not in OpenPGP's private/experimental-use
     * range (100-110), since the draft assigns a real numeric ID for this combination.
     * Mirrors {@code org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ML_KEM_768_X25519}.
     */
    public static final int ALGORITHM_ID = 35;

    private static final int X25519_LEN = 32;
    private static final int MLKEM_768_PUB_LEN = 1184;
    private static final int MLKEM_768_SEED_LEN = 64;
    private static final int MLKEM_768_CT_LEN = 1088;

    public static final int COMPOSITE_PUBLIC_KEY_LEN = X25519_LEN + MLKEM_768_PUB_LEN; // 1216
    public static final int COMPOSITE_SECRET_KEY_LEN = X25519_LEN + MLKEM_768_SEED_LEN; // 96

    private static final byte[] DOM_SEP = asciiBytes("OpenPGPCompositeKDFv1"); // 21 octets, per spec

    private CompositeMlKem768X25519() {
    }

    private static byte[] asciiBytes(String s) {
        byte[] out = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            out[i] = (byte) s.charAt(i);
        }
        return out;
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
     * Generates a fresh composite ML-KEM-768/X25519 key pair, encoded exactly as the draft's
     * public/secret key material sections describe (ML-KEM secret material kept in 64-octet
     * seed format, per FIPS 203 KeyGen steps 1-2, not the expanded form).
     */
    public static KeyMaterial generateKeyPair(SecureRandom random) {
        X25519PrivateKeyParameters x25519Priv = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters x25519Pub = x25519Priv.generatePublicKey();

        byte[] seed = new byte[MLKEM_768_SEED_LEN];
        random.nextBytes(seed);
        MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, seed);
        MLKEMPublicKeyParameters mlkemPub = mlkemPriv.getPublicKeyParameters();

        byte[] publicKeyBytes = concat(x25519Pub.getEncoded(), mlkemPub.getEncoded());
        byte[] secretKeyBytes = concat(x25519Priv.getEncoded(), seed);

        if (publicKeyBytes.length != COMPOSITE_PUBLIC_KEY_LEN) {
            throw new IllegalStateException("unexpected composite public key length: " + publicKeyBytes.length);
        }
        if (secretKeyBytes.length != COMPOSITE_SECRET_KEY_LEN) {
            throw new IllegalStateException("unexpected composite secret key length: " + secretKeyBytes.length);
        }

        return new KeyMaterial(publicKeyBytes, secretKeyBytes);
    }

    /**
     * Builds a composite ML-KEM-768/X25519 key pair deterministically from caller-supplied
     * seed material, instead of drawing fresh randomness -- used by raw PQC key material
     * import (see {@code RawPqcKeyImport}), where the point is that the same seed always
     * reproduces the same key. Otherwise byte-for-byte the same construction as
     * {@link #generateKeyPair}.
     *
     * @param classicalSeed raw X25519 secret key, exactly {@code X25519_LEN} (32) octets
     * @param pqSeed ML-KEM-768 seed ({@code d || z}), exactly {@code MLKEM_768_SEED_LEN} (64) octets
     * @throws IllegalArgumentException if either seed has the wrong length
     */
    public static KeyMaterial generateKeyPairFromSeed(byte[] classicalSeed, byte[] pqSeed) {
        if (classicalSeed.length != X25519_LEN) {
            throw new IllegalArgumentException(
                    "bad X25519 seed length: " + classicalSeed.length + ", expected " + X25519_LEN);
        }
        if (pqSeed.length != MLKEM_768_SEED_LEN) {
            throw new IllegalArgumentException(
                    "bad ML-KEM-768 seed length: " + pqSeed.length + ", expected " + MLKEM_768_SEED_LEN);
        }

        X25519PrivateKeyParameters x25519Priv = new X25519PrivateKeyParameters(classicalSeed);
        X25519PublicKeyParameters x25519Pub = x25519Priv.generatePublicKey();

        MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, pqSeed);
        MLKEMPublicKeyParameters mlkemPub = mlkemPriv.getPublicKeyParameters();

        byte[] publicKeyBytes = concat(x25519Pub.getEncoded(), mlkemPub.getEncoded());
        byte[] secretKeyBytes = concat(classicalSeed, pqSeed);

        if (publicKeyBytes.length != COMPOSITE_PUBLIC_KEY_LEN) {
            throw new IllegalStateException("unexpected composite public key length: " + publicKeyBytes.length);
        }
        if (secretKeyBytes.length != COMPOSITE_SECRET_KEY_LEN) {
            throw new IllegalStateException("unexpected composite secret key length: " + secretKeyBytes.length);
        }

        return new KeyMaterial(publicKeyBytes, secretKeyBytes);
    }

    /**
     * Wraps a raw content-encryption session key to a recipient's composite public key,
     * producing the v3 PKESK algorithm-specific field bytes (see class Javadoc for layout).
     *
     * @param recipientCompositePublicKeyBytes recipient's public key material (1216 octets)
     * @param symAlgId the plaintext (v3 PKESK) symmetric algorithm ID of {@code sessionKey};
     *                  per the draft this MUST be AES-128/192/256 (algorithm IDs 7/8/9)
     * @param sessionKey the raw content-encryption key octets (not framed with algorithm
     *                    ID or checksum -- that framing is not used by this scheme)
     */
    public static byte[] encryptSessionKey(byte[] recipientCompositePublicKeyBytes, byte symAlgId,
                                            byte[] sessionKey, SecureRandom random) {
        if (recipientCompositePublicKeyBytes.length != COMPOSITE_PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("bad composite public key length: "
                    + recipientCompositePublicKeyBytes.length);
        }

        byte[] recipientX25519PubBytes = slice(recipientCompositePublicKeyBytes, 0, X25519_LEN);
        byte[] recipientMlKemPubBytes = slice(recipientCompositePublicKeyBytes, X25519_LEN, MLKEM_768_PUB_LEN);

        X25519PublicKeyParameters recipientX25519Pub = new X25519PublicKeyParameters(recipientX25519PubBytes);
        MLKEMPublicKeyParameters recipientMlKemPub =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, recipientMlKemPubBytes);

        // Ephemeral X25519 key pair; its public key becomes "ecdhCipherText" on the wire.
        X25519PrivateKeyParameters ephemeralPriv = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters ephemeralPub = ephemeralPriv.generatePublicKey();
        byte[] ecdhCipherText = ephemeralPub.getEncoded();

        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ephemeralPriv);
        byte[] ecdhKeyShare = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(recipientX25519Pub, ecdhKeyShare, 0);

        MLKEMGenerator mlkemGenerator = new MLKEMGenerator(random);
        SecretWithEncapsulation encapsulated = mlkemGenerator.generateEncapsulated(recipientMlKemPub);
        byte[] mlkemCipherText = encapsulated.getEncapsulation();
        byte[] mlkemKeyShare = encapsulated.getSecret();

        byte[] kek = deriveKek(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, recipientX25519PubBytes);

        byte[] wrappedSessionKey = rfc3394Wrap(kek, sessionKey);

        int lenOctet = 1 + wrappedSessionKey.length; // symAlgId (1) + C
        if (lenOctet > 0xFF) {
            throw new IllegalStateException("session key too large for v3 PKESK length octet: " + lenOctet);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(
                ecdhCipherText.length + mlkemCipherText.length + 2 + wrappedSessionKey.length);
        out.write(ecdhCipherText, 0, ecdhCipherText.length);
        out.write(mlkemCipherText, 0, mlkemCipherText.length);
        out.write(lenOctet);
        out.write(symAlgId);
        out.write(wrappedSessionKey, 0, wrappedSessionKey.length);
        return out.toByteArray();
    }

    /**
     * Unwraps the session key from v3 PKESK algorithm-specific field bytes, given the
     * recipient's composite secret key.
     *
     * @param recipientCompositeSecretKeyBytes recipient's secret key material (96 octets)
     * @param pkeskAlgorithmSpecificData the {@code ecdhCipherText || mlkemCipherText ||
     *        len || symAlgId || C} bytes exactly as they appear in the PKESK packet
     * @param expectedSessionKeyLength if positive, the decoded session key length is
     *        checked against this value (the draft's mandated v3 PKESK length check); pass
     *        0 to skip this check when the expected length isn't known up front
     * @throws InvalidCipherTextException if the RFC 3394 key-wrap integrity check fails
     *         (tampered ciphertext or wrong key)
     */
    public static byte[] decryptSessionKey(byte[] recipientCompositeSecretKeyBytes,
                                            byte[] pkeskAlgorithmSpecificData,
                                            int expectedSessionKeyLength) throws InvalidCipherTextException {
        if (recipientCompositeSecretKeyBytes.length != COMPOSITE_SECRET_KEY_LEN) {
            throw new IllegalArgumentException("bad composite secret key length: "
                    + recipientCompositeSecretKeyBytes.length);
        }
        int minimumLength = X25519_LEN + MLKEM_768_CT_LEN + 2;
        if (pkeskAlgorithmSpecificData.length < minimumLength) {
            throw new IllegalArgumentException("PKESK algorithm-specific data too short");
        }

        byte[] x25519SecBytes = slice(recipientCompositeSecretKeyBytes, 0, X25519_LEN);
        byte[] mlkemSeed = slice(recipientCompositeSecretKeyBytes, X25519_LEN, MLKEM_768_SEED_LEN);

        X25519PrivateKeyParameters x25519Priv = new X25519PrivateKeyParameters(x25519SecBytes);
        X25519PublicKeyParameters x25519Pub = x25519Priv.generatePublicKey();
        MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, mlkemSeed);

        int off = 0;
        byte[] ecdhCipherText = slice(pkeskAlgorithmSpecificData, off, X25519_LEN);
        off += X25519_LEN;
        byte[] mlkemCipherText = slice(pkeskAlgorithmSpecificData, off, MLKEM_768_CT_LEN);
        off += MLKEM_768_CT_LEN;
        int lenOctet = pkeskAlgorithmSpecificData[off++] & 0xFF;
        int remaining = pkeskAlgorithmSpecificData.length - off;
        if (remaining != lenOctet) {
            throw new IllegalArgumentException("PKESK length octet (" + lenOctet
                    + ") does not match remaining bytes (" + remaining + ")");
        }
        int symAlgId = pkeskAlgorithmSpecificData[off++] & 0xFF;
        byte[] wrappedSessionKey = slice(pkeskAlgorithmSpecificData, off, pkeskAlgorithmSpecificData.length - off);

        X25519PublicKeyParameters ephemeralPub = new X25519PublicKeyParameters(ecdhCipherText);
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(x25519Priv);
        byte[] ecdhKeyShare = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(ephemeralPub, ecdhKeyShare, 0);

        MLKEMExtractor extractor = new MLKEMExtractor(mlkemPriv);
        byte[] mlkemKeyShare = extractor.extractSecret(mlkemCipherText);

        byte[] kek = deriveKek(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, x25519Pub.getEncoded());

        byte[] sessionKey = rfc3394Unwrap(kek, wrappedSessionKey);

        if (expectedSessionKeyLength > 0 && sessionKey.length != expectedSessionKeyLength) {
            throw new IllegalArgumentException("unwrapped session key length (" + sessionKey.length
                    + ") does not match expected length (" + expectedSessionKeyLength
                    + ") for symmetric algorithm ID " + symAlgId);
        }

        return sessionKey;
    }

    /**
     * Returns the plaintext (v3 PKESK) symmetric algorithm ID embedded in a PKESK's
     * algorithm-specific data, without performing any decryption -- exactly as BC's own
     * {@code AbstractPublicKeyDataDecryptorFactory} reads it directly off the wire for the
     * X25519/X448 cases (that byte is never encrypted for this scheme, same as for those).
     * Used by the real-app PGP decryption call site ({@code CompositeMlKem768X25519PublicKeyDataDecryptorFactory})
     * to reconstruct the classical {@code [symAlgId][sessionKey][checksum]} session-info
     * framing that BC's generic {@code PGPPublicKeyEncryptedData} machinery expects for any
     * algorithm ID it doesn't special-case (i.e. every algorithm other than X25519/X448).
     *
     * @param pkeskAlgorithmSpecificData the PKESK's algorithm-specific field bytes
     * @throws IllegalArgumentException if the data is too short to contain a symAlgId octet
     */
    public static int extractPlaintextSymAlgId(byte[] pkeskAlgorithmSpecificData) {
        int off = X25519_LEN + MLKEM_768_CT_LEN + 1; // ecdhCipherText || mlkemCipherText || len
        if (pkeskAlgorithmSpecificData.length <= off) {
            throw new IllegalArgumentException("PKESK algorithm-specific data too short to contain symAlgId");
        }
        return pkeskAlgorithmSpecificData[off] & 0xFF;
    }

    /** {@code multiKeyCombine(...)} per the draft's "Key Combiner" section, verbatim. */
    static byte[] deriveKek(byte[] mlkemKeyShare, byte[] ecdhKeyShare, byte[] ecdhCipherText,
                            byte[] ecdhPublicKey) {
        SHA3Digest digest = new SHA3Digest(256);
        digest.update(mlkemKeyShare, 0, mlkemKeyShare.length);
        digest.update(ecdhKeyShare, 0, ecdhKeyShare.length);
        digest.update(ecdhCipherText, 0, ecdhCipherText.length);
        digest.update(ecdhPublicKey, 0, ecdhPublicKey.length);
        digest.update((byte) ALGORITHM_ID);
        digest.update(DOM_SEP, 0, DOM_SEP.length);
        digest.update((byte) DOM_SEP.length);
        byte[] kek = new byte[digest.getDigestSize()];
        digest.doFinal(kek, 0);
        return kek;
    }

    private static byte[] rfc3394Wrap(byte[] kek, byte[] keyData) {
        RFC3394WrapEngine wrapEngine = new RFC3394WrapEngine(new AESEngine());
        wrapEngine.init(true, new KeyParameter(kek));
        return wrapEngine.wrap(keyData, 0, keyData.length);
    }

    private static byte[] rfc3394Unwrap(byte[] kek, byte[] wrapped) throws InvalidCipherTextException {
        RFC3394WrapEngine wrapEngine = new RFC3394WrapEngine(new AESEngine());
        wrapEngine.init(false, new KeyParameter(kek));
        return wrapEngine.unwrap(wrapped, 0, wrapped.length);
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
