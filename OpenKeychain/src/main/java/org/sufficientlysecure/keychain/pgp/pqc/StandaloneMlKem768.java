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
 * Standalone (non-composite, closed-ecosystem) ML-KEM-768 OpenPGP encryption -- no classical
 * (ECDH) component, no AND-combiner, no concatenation. This is <b>not</b> defined by
 * draft-ietf-openpgp-pqc-17 or any other spec: the draft only defines composite ML-KEM
 * (algorithm IDs 35/36, see {@link CompositeMlKem768X25519}/{@link CompositeMlKem1024X448}).
 * This is a private-use algorithm ID assignment (100, within OpenPGP's 100-110
 * private/experimental-use range) made by this codebase for a closed-ecosystem deployment mode
 * where every peer is known to run this same fork -- see
 * docs/superpowers/specs/2026-07-07-pqc-migration-design.md (Standalone/Closed-Ecosystem Mode
 * section) for the full design rationale and decisions log.
 *
 * <p><b>Non-standard warning:</b> keys and messages using this algorithm ID will not
 * interoperate with GnuPG, Sequoia, RNP, or any other OpenPGP implementation -- including any
 * future implementation of draft-ietf-openpgp-pqc-17 itself, since that draft never defines
 * this code point. Every call site that surfaces this algorithm to a human (key generation
 * UI, key listing) must make this explicit; see {@code SaveKeyringParcel.Algorithm} and
 * {@code KeyFormattingUtils} for where that flag/string is carried through the data model.
 *
 * <p>This class mirrors {@link CompositeMlKem768X25519}'s structure closely (same BC ML-KEM
 * primitive calls, same seed-format secret-key convention) with the X25519 half and the KDF
 * combiner's ECDH terms simply removed -- it is a strict subset of the same primitive calls,
 * never a structurally different construction.
 *
 * <h3>Wire format (algorithm ID 100, OpenKeychain private-use assignment)</h3>
 * <ul>
 *   <li>Public key material: the raw ML-KEM-768 public key, 1184 octets, native encoding, no
 *       concatenation with anything else.</li>
 *   <li>Secret key material: the ML-KEM-768 secret key in <em>seed format</em> (64 octets,
 *       {@code d || z} per FIPS 203 §3.3), expanded via {@code ML-KEM.KeyGen_internal} only at
 *       point of use, never stored expanded -- same convention {@link CompositeMlKem768X25519}
 *       already established.</li>
 *   <li>PKESK (Public-Key Encrypted Session Key, packet type 1) algorithm-specific data:
 *       {@code mlkemCipherText (1088) || len(C,symAlgId) (1) || symAlgId (1, plaintext) || C},
 *       where {@code C} is the RFC 3394 AES-256 key-wrap of the raw content-encryption session
 *       key -- structurally identical to {@link CompositeMlKem768X25519}'s PKESK layout with
 *       the {@code ecdhCipherText} field simply absent (there is no ECDH half to contribute
 *       one).</li>
 * </ul>
 *
 * <h3>KEK derivation -- KDF over the raw ML-KEM shared secret, not raw-secret-as-key</h3>
 * <p>Standalone mode has no classical component and therefore no composite combiner to fall
 * back on. Using the raw ML-KEM shared secret directly as the AES-key-wrap key is defensible
 * per FIPS 203's own intended usage (the shared secret is already uniformly random and
 * cryptographically independent), but this class deliberately does not take that shortcut: it
 * would be an unprecedented departure from every other KEM path in this codebase (both
 * composite KEM classes always run their shared secret(s) through a domain-separated hash
 * before use as a key), and standard KEM/KDF hygiene -- see NIST SP 800-56C's own guidance on
 * running a raw DH/KEM shared secret through a KDF before use as a symmetric key, precisely to
 * bind the derived key to its algorithm/context and prevent cross-context or
 * algorithm-confusion key reuse -- argues for the same treatment here. So this class reuses the
 * *same* domain-separated-hash shape as {@link CompositeMlKem768X25519}'s combiner, just with
 * the ECDH terms dropped:
 * <pre>
 *   KEK = SHA3-256(mlkemKeyShare || mlkemCipherText || algId || domSep || len(domSep))
 * </pre>
 * where {@code domSep} is the UTF-8 string {@code "OpenKeychainStandaloneKEMKDFv1"} (30
 * octets) -- a <b>new, distinct</b> domain separator, deliberately not reusing the draft's
 * {@code "OpenPGPCompositeKDFv1"} string, since that string names a specific composite
 * construction this isn't, and colliding domain separators across two different constructions
 * is exactly the kind of confusion a domain separator exists to prevent. One separator is
 * shared across both standalone ML-KEM-768 (100) and ML-KEM-1024 (101), mirroring how one
 * separator is shared across composite algorithms 35/36 -- the {@code algId} octet already
 * disambiguates them.
 *
 * <h3>Version requirement -- v6-only, no v4 allowance</h3>
 * <p>This algorithm is v6-only by this codebase's own decision (there is no spec to carve a v4
 * allowance out of): every call site that constructs or parses an algorithm-100 key packet
 * enforces v6-only -- see {@code PublicKeyPacket}'s {@code EXPERIMENTAL_1} parse case,
 * {@code PgpKeyOperation}'s standalone-ML-KEM-768 key-generation path, and {@code
 * UncachedKeyRing#canonicalize}'s master-key/subkey version checks.
 */
public class StandaloneMlKem768 {

    /**
     * Private-use algorithm ID assigned by this codebase for standalone (non-composite)
     * ML-KEM-768 encryption. Mirrors
     * {@code org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EXPERIMENTAL_1}. Not IANA-registered,
     * not defined by draft-ietf-openpgp-pqc-17 -- see class Javadoc.
     */
    public static final int ALGORITHM_ID = 100;

    private static final int MLKEM_768_PUB_LEN = 1184;
    private static final int MLKEM_768_SEED_LEN = 64;
    private static final int MLKEM_768_CT_LEN = 1088;

    public static final int PUBLIC_KEY_LEN = MLKEM_768_PUB_LEN;
    public static final int SECRET_KEY_LEN = MLKEM_768_SEED_LEN;

    private static final byte[] DOM_SEP = asciiBytes("OpenKeychainStandaloneKEMKDFv1"); // 30 octets

    private StandaloneMlKem768() {
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
     * Generates a fresh standalone ML-KEM-768 key pair (ML-KEM secret material kept in
     * 64-octet seed format, per FIPS 203 KeyGen steps 1-2, not the expanded form).
     */
    public static KeyMaterial generateKeyPair(SecureRandom random) {
        byte[] seed = new byte[MLKEM_768_SEED_LEN];
        random.nextBytes(seed);
        MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, seed);
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
     * Wraps a raw content-encryption session key to a recipient's standalone ML-KEM-768 public
     * key, producing the PKESK algorithm-specific field bytes (see class Javadoc for layout).
     *
     * @param recipientPublicKeyBytes recipient's public key material (1184 octets)
     * @param symAlgId the plaintext symmetric algorithm ID of {@code sessionKey}
     * @param sessionKey the raw content-encryption key octets (not framed with algorithm ID or
     *                    checksum -- that framing is not used by this scheme)
     */
    public static byte[] encryptSessionKey(byte[] recipientPublicKeyBytes, byte symAlgId,
                                            byte[] sessionKey, SecureRandom random) {
        if (recipientPublicKeyBytes.length != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("bad public key length: " + recipientPublicKeyBytes.length);
        }

        MLKEMPublicKeyParameters recipientMlKemPub =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, recipientPublicKeyBytes);

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
     * standalone ML-KEM-768 secret key.
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
        int minimumLength = MLKEM_768_CT_LEN + 2;
        if (pkeskAlgorithmSpecificData.length < minimumLength) {
            throw new IllegalArgumentException("PKESK algorithm-specific data too short");
        }

        MLKEMPrivateKeyParameters mlkemPriv =
                new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, recipientSecretKeyBytes);

        int off = 0;
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
     * data, without performing any decryption -- same rationale as
     * {@link CompositeMlKem768X25519#extractPlaintextSymAlgId}, applied here with this
     * algorithm's own (ECDH-free) field layout.
     *
     * @param pkeskAlgorithmSpecificData the PKESK's algorithm-specific field bytes
     * @throws IllegalArgumentException if the data is too short to contain a symAlgId octet
     */
    public static int extractPlaintextSymAlgId(byte[] pkeskAlgorithmSpecificData) {
        int off = MLKEM_768_CT_LEN + 1; // mlkemCipherText || len
        if (pkeskAlgorithmSpecificData.length <= off) {
            throw new IllegalArgumentException("PKESK algorithm-specific data too short to contain symAlgId");
        }
        return pkeskAlgorithmSpecificData[off] & 0xFF;
    }

    /**
     * KEK derivation -- see class Javadoc's "KEK derivation" section for the full rationale
     * for why this KDF step exists even without a classical component to combine.
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
