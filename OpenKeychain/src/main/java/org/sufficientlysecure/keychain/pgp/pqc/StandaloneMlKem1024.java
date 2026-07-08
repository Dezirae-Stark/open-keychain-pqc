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
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * Standalone (non-composite, closed-ecosystem) ML-KEM-1024 OpenPGP encryption -- no classical
 * (ECDH) component, no AND-combiner, no concatenation. Structurally identical to
 * {@link StandaloneMlKem768} (see that class's Javadoc for the full design rationale, KEK
 * derivation reasoning, and non-standard-interop warning, all of which apply verbatim here),
 * just with the higher-security-category ML-KEM-1024 primitive and its own field lengths. This
 * is the category-5 sibling of the category-3 {@link StandaloneMlKem768}, mirroring how {@link
 * CompositeMlKem1024X448} is the category-5 sibling of {@link CompositeMlKem768X25519} in the
 * composite path.
 *
 * <p>This is <b>not</b> defined by draft-ietf-openpgp-pqc-17 or any other spec -- a private-use
 * algorithm ID assignment (101, within OpenPGP's 100-110 private/experimental-use range) made
 * by this codebase. See
 * docs/superpowers/specs/2026-07-07-pqc-migration-design.md (Standalone/Closed-Ecosystem Mode
 * section) for the design rationale.
 *
 * <h3>Wire format (algorithm ID 101, OpenKeychain private-use assignment)</h3>
 * <ul>
 *   <li>Public key material: the raw ML-KEM-1024 public key, 1568 octets, native encoding.</li>
 *   <li>Secret key material: the ML-KEM-1024 secret key in seed format (64 octets, {@code
 *       d || z} per FIPS 203 §3.3), expanded via {@code ML-KEM.KeyGen_internal} only at point
 *       of use.</li>
 *   <li>PKESK algorithm-specific data: {@code mlkemCipherText (1568) || len(C,symAlgId) (1) ||
 *       symAlgId (1, plaintext) || C}.</li>
 * </ul>
 *
 * <p>KEK derivation shares the identical KDF shape and the same domain separator as {@link
 * StandaloneMlKem768} (one separator across both 100 and 101, disambiguated by the
 * {@code algId} octet fed into the hash) -- see that class's Javadoc for the full rationale.
 */
public class StandaloneMlKem1024 {

    /**
     * Private-use algorithm ID assigned by this codebase for standalone (non-composite)
     * ML-KEM-1024 encryption. Mirrors
     * {@code org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EXPERIMENTAL_2}. Not IANA-registered,
     * not defined by draft-ietf-openpgp-pqc-17 -- see class Javadoc.
     */
    public static final int ALGORITHM_ID = 101;

    private static final int MLKEM_1024_PUB_LEN = 1568;
    private static final int MLKEM_1024_SEED_LEN = 64;
    private static final int MLKEM_1024_CT_LEN = 1568;

    public static final int PUBLIC_KEY_LEN = MLKEM_1024_PUB_LEN;
    public static final int SECRET_KEY_LEN = MLKEM_1024_SEED_LEN;

    // Same domain separator as StandaloneMlKem768 -- see that class's Javadoc for why one
    // separator is deliberately shared across both standalone ML-KEM algorithm IDs.
    private static final byte[] DOM_SEP = asciiBytes("OpenKeychainStandaloneKEMKDFv1"); // 30 octets

    private StandaloneMlKem1024() {
    }

    private static byte[] asciiBytes(String s) {
        byte[] out = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            out[i] = (byte) s.charAt(i);
        }
        return out;
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
     * Generates a fresh standalone ML-KEM-1024 key pair (ML-KEM secret material kept in
     * 64-octet seed format, per FIPS 203 KeyGen steps 1-2, not the expanded form).
     */
    public static KeyMaterial generateKeyPair(SecureRandom random) {
        byte[] seed = new byte[MLKEM_1024_SEED_LEN];
        random.nextBytes(seed);
        MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, seed);
        MLKEMPublicKeyParameters mlkemPub = mlkemPriv.getPublicKeyParameters();

        byte[] publicKeyBytes = mlkemPub.getEncoded();
        byte[] secretKeyBytes = seed;

        if (publicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalStateException("unexpected public key length: " + publicKeyBytes.length);
        }
        if (secretKeyBytes.length != SECRET_KEY_LEN) {
            throw new IllegalStateException("unexpected secret key length: " + secretKeyBytes.length);
        }

        return new KeyMaterial(publicKeyBytes, secretKeyBytes);
    }

    /**
     * Wraps a raw content-encryption session key to a recipient's standalone ML-KEM-1024
     * public key, producing the PKESK algorithm-specific field bytes (see class Javadoc).
     *
     * @param recipientPublicKeyBytes recipient's public key material (1568 octets)
     * @param symAlgId the plaintext symmetric algorithm ID of {@code sessionKey}
     * @param sessionKey the raw content-encryption key octets
     */
    public static byte[] encryptSessionKey(byte[] recipientPublicKeyBytes, byte symAlgId,
                                            byte[] sessionKey, SecureRandom random) {
        if (recipientPublicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("bad public key length: " + recipientPublicKeyBytes.length);
        }

        MLKEMPublicKeyParameters recipientMlKemPub =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, recipientPublicKeyBytes);

        MLKEMGenerator mlkemGenerator = new MLKEMGenerator(random);
        SecretWithEncapsulation encapsulated = mlkemGenerator.generateEncapsulated(recipientMlKemPub);
        byte[] mlkemCipherText = encapsulated.getEncapsulation();
        byte[] mlkemKeyShare = encapsulated.getSecret();

        byte[] kek = deriveKek(mlkemKeyShare, mlkemCipherText);

        byte[] wrappedSessionKey = rfc3394Wrap(kek, sessionKey);

        int lenOctet = 1 + wrappedSessionKey.length; // symAlgId (1) + C
        if (lenOctet > 0xFF) {
            throw new IllegalStateException("session key too large for PKESK length octet: " + lenOctet);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(
                mlkemCipherText.length + 2 + wrappedSessionKey.length);
        out.write(mlkemCipherText, 0, mlkemCipherText.length);
        out.write(lenOctet);
        out.write(symAlgId);
        out.write(wrappedSessionKey, 0, wrappedSessionKey.length);
        return out.toByteArray();
    }

    /**
     * Unwraps the session key from PKESK algorithm-specific field bytes, given the recipient's
     * standalone ML-KEM-1024 secret key.
     *
     * @param recipientSecretKeyBytes recipient's secret key material (64 octets, seed format)
     * @param pkeskAlgorithmSpecificData the {@code mlkemCipherText || len || symAlgId || C}
     *        bytes exactly as they appear in the PKESK packet
     * @param expectedSessionKeyLength if positive, the decoded session key length is checked
     *        against this value; pass 0 to skip this check when not known up front
     * @throws InvalidCipherTextException if the RFC 3394 key-wrap integrity check fails
     *         (tampered ciphertext or wrong key)
     */
    public static byte[] decryptSessionKey(byte[] recipientSecretKeyBytes,
                                            byte[] pkeskAlgorithmSpecificData,
                                            int expectedSessionKeyLength) throws InvalidCipherTextException {
        if (recipientSecretKeyBytes.length != SECRET_KEY_LEN) {
            throw new IllegalArgumentException("bad secret key length: " + recipientSecretKeyBytes.length);
        }
        int minimumLength = MLKEM_1024_CT_LEN + 2;
        if (pkeskAlgorithmSpecificData.length < minimumLength) {
            throw new IllegalArgumentException("PKESK algorithm-specific data too short");
        }

        MLKEMPrivateKeyParameters mlkemPriv =
                new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, recipientSecretKeyBytes);

        int off = 0;
        byte[] mlkemCipherText = slice(pkeskAlgorithmSpecificData, off, MLKEM_1024_CT_LEN);
        off += MLKEM_1024_CT_LEN;
        int lenOctet = pkeskAlgorithmSpecificData[off++] & 0xFF;
        int remaining = pkeskAlgorithmSpecificData.length - off;
        if (remaining != lenOctet) {
            throw new IllegalArgumentException("PKESK length octet (" + lenOctet
                    + ") does not match remaining bytes (" + remaining + ")");
        }
        int symAlgId = pkeskAlgorithmSpecificData[off++] & 0xFF;
        byte[] wrappedSessionKey = slice(pkeskAlgorithmSpecificData, off, pkeskAlgorithmSpecificData.length - off);

        MLKEMExtractor extractor = new MLKEMExtractor(mlkemPriv);
        byte[] mlkemKeyShare = extractor.extractSecret(mlkemCipherText);

        byte[] kek = deriveKek(mlkemKeyShare, mlkemCipherText);

        byte[] sessionKey = rfc3394Unwrap(kek, wrappedSessionKey);

        if (expectedSessionKeyLength > 0 && sessionKey.length != expectedSessionKeyLength) {
            throw new IllegalArgumentException("unwrapped session key length (" + sessionKey.length
                    + ") does not match expected length (" + expectedSessionKeyLength
                    + ") for symmetric algorithm ID " + symAlgId);
        }

        return sessionKey;
    }

    /**
     * Returns the plaintext symmetric algorithm ID embedded in a PKESK's algorithm-specific
     * data, without performing any decryption -- see
     * {@link StandaloneMlKem768#extractPlaintextSymAlgId} for the identical rationale.
     *
     * @param pkeskAlgorithmSpecificData the PKESK's algorithm-specific field bytes
     * @throws IllegalArgumentException if the data is too short to contain a symAlgId octet
     */
    public static int extractPlaintextSymAlgId(byte[] pkeskAlgorithmSpecificData) {
        int off = MLKEM_1024_CT_LEN + 1; // mlkemCipherText || len
        if (pkeskAlgorithmSpecificData.length <= off) {
            throw new IllegalArgumentException("PKESK algorithm-specific data too short to contain symAlgId");
        }
        return pkeskAlgorithmSpecificData[off] & 0xFF;
    }

    /**
     * KEK derivation -- see {@link StandaloneMlKem768}'s class Javadoc "KEK derivation"
     * section for the full rationale.
     */
    static byte[] deriveKek(byte[] mlkemKeyShare, byte[] mlkemCipherText) {
        SHA3Digest digest = new SHA3Digest(256);
        digest.update(mlkemKeyShare, 0, mlkemKeyShare.length);
        digest.update(mlkemCipherText, 0, mlkemCipherText.length);
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

    private static byte[] slice(byte[] a, int off, int len) {
        return Arrays.copyOfRange(a, off, off + len);
    }
}
