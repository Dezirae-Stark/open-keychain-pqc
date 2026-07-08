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
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * Composite ML-KEM-1024/X448 OpenPGP encryption, implemented directly against
 * draft-ietf-openpgp-pqc-17 (the IETF OpenPGP WG's own git repo,
 * https://github.com/openpgp-pqc/draft-openpgp-pqc, tag draft-ietf-openpgp-pqc-17;
 * datatracker/ietf.org text renderings are not reachable from this build environment,
 * see docs/superpowers/specs/2026-07-07-pqc-migration-design.md for provenance). This is the
 * SHOULD-implement composite KEM of the draft (algorithm ID 36) -- the
 * higher-security-category sibling of the MUST-implement ML-KEM-768+X25519 (algorithm ID 35,
 * see {@link CompositeMlKem768X25519}), which this class mirrors structurally.
 *
 * <p>This is hand-built wire-format logic, not inherited from Bouncy Castle: BC 1.84 has
 * ML-KEM-1024/X448 *primitives* (used here) but no OpenPGP-packet-level composite KEM support
 * at all -- exactly as already established for {@link CompositeMlKem768X25519}. This class
 * deliberately imports ML-KEM off the same {@code org.bouncycastle.pqc.crypto.mlkem} package
 * (class-level {@code @Deprecated}, confirmed by {@code javap}) that {@link
 * CompositeMlKem768X25519} already uses -- there's a newer, non-deprecated
 * {@code org.bouncycastle.crypto.params}/{@code org.bouncycastle.crypto.kems} ML-KEM surface
 * in this BC release, but moving to it is a decision that affects both composite KEM classes
 * together (a mixed-surface split would be its own hazard), so it is out of scope for this
 * change and left for a dedicated migration.
 *
 * <p>X448 (unlike X25519) has no bearing on the KEM math itself beyond key/agreement sizes --
 * {@link X448Agreement} has the identical shape as {@code X25519Agreement} (no-arg
 * constructor, {@code init}/{@code calculateAgreement}), just with 56-octet keys/agreement
 * output instead of 32.
 *
 * <h3>Wire format (algorithm ID 36, per the draft's IANA table)</h3>
 * <ul>
 *   <li>Public key material (fixed-length octet strings, concatenated): X448 public key
 *       (56 octets) || ML-KEM-1024 public key (1568 octets).</li>
 *   <li>Secret key material: X448 secret key (56 octets) || ML-KEM-1024 secret key in
 *       <em>seed format</em> (64 octets, {@code d || z} per FIPS 203 §3.3), expanded via
 *       {@code ML-KEM.KeyGen_internal} only at point of use, never stored expanded.</li>
 *   <li>PKESK (Public-Key Encrypted Session Key, packet type 1) v3 algorithm-specific data:
 *       {@code ecdhCipherText (56) || mlkemCipherText (1568) || len(C,symAlgId) (1) ||
 *       symAlgId (1, v3 only, plaintext) || C}, where {@code C} is the RFC 3394 AES-256
 *       key-wrap of the raw content-encryption session key -- same framing rationale as
 *       {@link CompositeMlKem768X25519}'s Javadoc explains for algorithm 35.</li>
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
 * {@code ecdhPublicKey} is the recipient's static X448 public key. The draft defines exactly
 * one {@code multiKeyCombine} construction, shared verbatim between algorithm IDs 35 and 36
 * (differentiated only by the {@code algId} octet fed into the hash) -- confirmed by the
 * single occurrence of this construction in the fetched draft text, and empirically exercised
 * by the draft's own published ID-31+36 test vector, which uses the identical field names as
 * the ID-30+35 vectors.
 *
 * <h3>Version requirement -- v6-only, no v4 allowance (checked explicitly, not assumed)</h3>
 * <p>Unlike {@link CompositeMlKem768X25519} (algorithm 35), which the draft explicitly allows
 * in v4 encryption-capable subkeys, algorithm 36 has no such carve-out: the draft states "The
 * composite ML-KEM-1024 + X448 (algorithm ID 36) MUST be used only with v6 keys" in direct
 * textual contrast to the immediately preceding sentence granting algorithm 35 alone the v4
 * allowance. This class itself is version-agnostic (it only handles the composite key/PKESK
 * byte encoding), but every call site that constructs or parses algorithm-36 key packets
 * enforces v6-only -- see {@code PublicKeyPacket}'s {@code ML_KEM_1024_X448} parse case,
 * {@code PgpKeyOperation#createCompositeMlKem1024X448KeyPair}, and {@code
 * UncachedKeyRing#canonicalize}'s master-key/subkey version checks.
 */
public class CompositeMlKem1024X448 {

    /**
     * Algorithm ID assigned by draft-ietf-openpgp-pqc-17 for composite ML-KEM-1024+X448.
     * A SHOULD-implement algorithm per the draft; mirrors
     * {@code org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ML_KEM_1024_X448}.
     */
    public static final int ALGORITHM_ID = 36;

    private static final int X448_LEN = 56;
    private static final int MLKEM_1024_PUB_LEN = 1568;
    private static final int MLKEM_1024_SEED_LEN = 64;
    private static final int MLKEM_1024_CT_LEN = 1568;

    public static final int COMPOSITE_PUBLIC_KEY_LEN = X448_LEN + MLKEM_1024_PUB_LEN; // 1624
    public static final int COMPOSITE_SECRET_KEY_LEN = X448_LEN + MLKEM_1024_SEED_LEN; // 120

    private static final byte[] DOM_SEP = asciiBytes("OpenPGPCompositeKDFv1"); // 21 octets, per spec

    private CompositeMlKem1024X448() {
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
     * Generates a fresh composite ML-KEM-1024/X448 key pair, encoded exactly as the draft's
     * public/secret key material sections describe (ML-KEM secret material kept in 64-octet
     * seed format, per FIPS 203 KeyGen steps 1-2, not the expanded form).
     */
    public static KeyMaterial generateKeyPair(SecureRandom random) {
        X448PrivateKeyParameters x448Priv = new X448PrivateKeyParameters(random);
        X448PublicKeyParameters x448Pub = x448Priv.generatePublicKey();

        byte[] seed = new byte[MLKEM_1024_SEED_LEN];
        random.nextBytes(seed);
        MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, seed);
        MLKEMPublicKeyParameters mlkemPub = mlkemPriv.getPublicKeyParameters();

        byte[] publicKeyBytes = concat(x448Pub.getEncoded(), mlkemPub.getEncoded());
        byte[] secretKeyBytes = concat(x448Priv.getEncoded(), seed);

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
     * @param recipientCompositePublicKeyBytes recipient's public key material (1624 octets)
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

        byte[] recipientX448PubBytes = slice(recipientCompositePublicKeyBytes, 0, X448_LEN);
        byte[] recipientMlKemPubBytes = slice(recipientCompositePublicKeyBytes, X448_LEN, MLKEM_1024_PUB_LEN);

        X448PublicKeyParameters recipientX448Pub = new X448PublicKeyParameters(recipientX448PubBytes);
        MLKEMPublicKeyParameters recipientMlKemPub =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, recipientMlKemPubBytes);

        // Ephemeral X448 key pair; its public key becomes "ecdhCipherText" on the wire.
        X448PrivateKeyParameters ephemeralPriv = new X448PrivateKeyParameters(random);
        X448PublicKeyParameters ephemeralPub = ephemeralPriv.generatePublicKey();
        byte[] ecdhCipherText = ephemeralPub.getEncoded();

        X448Agreement agreement = new X448Agreement();
        agreement.init(ephemeralPriv);
        byte[] ecdhKeyShare = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(recipientX448Pub, ecdhKeyShare, 0);

        MLKEMGenerator mlkemGenerator = new MLKEMGenerator(random);
        SecretWithEncapsulation encapsulated = mlkemGenerator.generateEncapsulated(recipientMlKemPub);
        byte[] mlkemCipherText = encapsulated.getEncapsulation();
        byte[] mlkemKeyShare = encapsulated.getSecret();

        byte[] kek = deriveKek(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, recipientX448PubBytes);

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
     * @param recipientCompositeSecretKeyBytes recipient's secret key material (120 octets)
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
        int minimumLength = X448_LEN + MLKEM_1024_CT_LEN + 2;
        if (pkeskAlgorithmSpecificData.length < minimumLength) {
            throw new IllegalArgumentException("PKESK algorithm-specific data too short");
        }

        byte[] x448SecBytes = slice(recipientCompositeSecretKeyBytes, 0, X448_LEN);
        byte[] mlkemSeed = slice(recipientCompositeSecretKeyBytes, X448_LEN, MLKEM_1024_SEED_LEN);

        X448PrivateKeyParameters x448Priv = new X448PrivateKeyParameters(x448SecBytes);
        X448PublicKeyParameters x448Pub = x448Priv.generatePublicKey();
        MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, mlkemSeed);

        int off = 0;
        byte[] ecdhCipherText = slice(pkeskAlgorithmSpecificData, off, X448_LEN);
        off += X448_LEN;
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

        X448PublicKeyParameters ephemeralPub = new X448PublicKeyParameters(ecdhCipherText);
        X448Agreement agreement = new X448Agreement();
        agreement.init(x448Priv);
        byte[] ecdhKeyShare = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(ephemeralPub, ecdhKeyShare, 0);

        MLKEMExtractor extractor = new MLKEMExtractor(mlkemPriv);
        byte[] mlkemKeyShare = extractor.extractSecret(mlkemCipherText);

        byte[] kek = deriveKek(mlkemKeyShare, ecdhKeyShare, ecdhCipherText, x448Pub.getEncoded());

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
     * algorithm-specific data, without performing any decryption -- see
     * {@link CompositeMlKem768X25519#extractPlaintextSymAlgId} for the identical rationale,
     * applied here with this algorithm's own field lengths.
     *
     * @param pkeskAlgorithmSpecificData the PKESK's algorithm-specific field bytes
     * @throws IllegalArgumentException if the data is too short to contain a symAlgId octet
     */
    public static int extractPlaintextSymAlgId(byte[] pkeskAlgorithmSpecificData) {
        int off = X448_LEN + MLKEM_1024_CT_LEN + 1; // ecdhCipherText || mlkemCipherText || len
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
