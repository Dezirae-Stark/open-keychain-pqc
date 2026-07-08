/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
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


import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.bcpg.OpaqueSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.AuthenticationSignatureGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.CachingDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.EdDsaAuthenticationContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.NfcSyncPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.SessionKeySecretKeyDecryptorBuilder;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlDsa65Ed25519ContentSignerBuilder;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlKem768X25519;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlKem768X25519PublicKeyDataDecryptorFactory;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.Passphrase;
import timber.log.Timber;


/**
 * Wrapper for a PGPSecretKey.
 * <p/>
 * This object can only be obtained from a WrappedSecretKeyRing, and stores a
 * back reference to its parent.
 * <p/>
 * This class represents known secret keys which are stored in the database.
 * All "crypto operations using a known secret key" should be implemented in
 * this class, to ensure on type level that these operations are performed on
 * properly imported secret keys only.
 */
public class CanonicalizedSecretKey extends CanonicalizedPublicKey {

    private final PGPSecretKey mSecretKey;
    private PGPPrivateKey mPrivateKey = null;

    private int mPrivateKeyState = PRIVATE_KEY_STATE_LOCKED;
    final private static int PRIVATE_KEY_STATE_LOCKED = 0;
    final private static int PRIVATE_KEY_STATE_UNLOCKED = 1;
    final private static int PRIVATE_KEY_STATE_DIVERT_TO_CARD = 2;

    CanonicalizedSecretKey(CanonicalizedSecretKeyRing ring, PGPSecretKey key) {
        super(ring, key.getPublicKey());
        mSecretKey = key;
    }

    public CanonicalizedSecretKeyRing getRing() {
        return (CanonicalizedSecretKeyRing) mRing;
    }

    public enum SecretKeyType {
        UNAVAILABLE(0), GNU_DUMMY(1), PASSPHRASE(2), PASSPHRASE_EMPTY(3), DIVERT_TO_CARD(4);

        final int mNum;

        SecretKeyType(int num) {
            mNum = num;
        }

        public static SecretKeyType fromNum(int num) {
            switch (num) {
                case 1:
                    return GNU_DUMMY;
                case 2:
                    return PASSPHRASE;
                case 3:
                    return PASSPHRASE_EMPTY;
                case 4:
                    return DIVERT_TO_CARD;
                // if this case happens, it's probably a check from a database value
                default:
                    return UNAVAILABLE;
            }
        }

        public int getNum() {
            return mNum;
        }

        public boolean isUsable() {
            return this != UNAVAILABLE && this != GNU_DUMMY;
        }

        /** Compares by "usability", which basically compares how independently usable
         * two SecretKeyTypes are. The order is roughly this:
         *
         * empty passphrase < passphrase/others < divert < stripped
         *
         */
        public int compareUsability(SecretKeyType other) {
            // if one is usable but the other isn't, the usable one comes first
            if (isUsable() ^ other.isUsable()) {
                return isUsable() ? -1 : 1;
            }
            // if one is a divert-to-card but the other isn't, the non-divert one comes first
            if ((this == DIVERT_TO_CARD) ^ (other == DIVERT_TO_CARD)) {
                return this != DIVERT_TO_CARD ? -1 : 1;
            }
            // if one requires a passphrase but another doesn't, the one without a passphrase comes first
            if ((this == PASSPHRASE_EMPTY) ^ (other == PASSPHRASE_EMPTY)) {
                return this == PASSPHRASE_EMPTY ? -1 : 1;
            }
            // all other (current) cases are equal
            return 0;
        }

    }

    /** This method returns the SecretKeyType for this secret key, testing for an empty
     * passphrase in the process.
     *
     * This method can potentially take a LONG time (i.e. seconds), so it should only
     * ever be called by {@link KeyWritableRepository} for the purpose of caching its output
     * in the database.
     */
    public SecretKeyType getSecretKeyTypeSuperExpensive() {
        S2K s2k = mSecretKey.getS2K();
        if (s2k != null && s2k.getType() == S2K.GNU_DUMMY_S2K) {
            // divert to card is special
            if (s2k.getProtectionMode() == S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD) {
                return SecretKeyType.DIVERT_TO_CARD;
            }
            // no matter the exact protection mode, it's some kind of dummy key
            return SecretKeyType.GNU_DUMMY;
        }

        try {
            PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider(
                    Constants.BOUNCY_CASTLE_PROVIDER_NAME).build("".toCharArray());
            // If this doesn't throw
            mSecretKey.extractPrivateKey(keyDecryptor);
            // It means the passphrase is empty
            return SecretKeyType.PASSPHRASE_EMPTY;
        } catch (PGPException e) {
            // Otherwise, it's just a regular ol' passphrase
            return SecretKeyType.PASSPHRASE;
        }
    }

    /**
     * Returns true on right passphrase
     */
    public boolean unlock(final Passphrase passphrase) throws PgpGeneralException {
        // handle keys on OpenPGP cards like they were unlocked
        S2K s2k = mSecretKey.getS2K();
        if (s2k != null
                && s2k.getType() == S2K.GNU_DUMMY_S2K
                && s2k.getProtectionMode() == S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD) {
            mPrivateKeyState = PRIVATE_KEY_STATE_DIVERT_TO_CARD;
            return true;
        }

        // try to extract keys using the passphrase
        try {

            int keyEncryptionAlgorithm = mSecretKey.getKeyEncryptionAlgorithm();
            if (keyEncryptionAlgorithm == SymmetricKeyAlgorithmTags.NULL) {
                mPrivateKey = mSecretKey.extractPrivateKey(null);
                mPrivateKeyState = PRIVATE_KEY_STATE_UNLOCKED;
                return true;
            }

            byte[] sessionKey;
            sessionKey = passphrase.getCachedSessionKeyForParameters(keyEncryptionAlgorithm, s2k);
            if (sessionKey == null) {
                PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider(
                        Constants.BOUNCY_CASTLE_PROVIDER_NAME).build(passphrase.getCharArray());
                // this operation is EXPENSIVE, so we cache its result in the passed Passphrase object!
                sessionKey = keyDecryptor.makeKeyFromPassPhrase(keyEncryptionAlgorithm, s2k);
                passphrase.addCachedSessionKeyForParameters(keyEncryptionAlgorithm, s2k, sessionKey);
            }

            PBESecretKeyDecryptor keyDecryptor = new SessionKeySecretKeyDecryptorBuilder()
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME).build(sessionKey);
            mPrivateKey = mSecretKey.extractPrivateKey(keyDecryptor);
            mPrivateKeyState = PRIVATE_KEY_STATE_UNLOCKED;
        } catch (PGPException e) {
            Timber.e(e, "Error extracting private key!");
            return false;
        }
        if (mPrivateKey == null) {
            throw new PgpGeneralException("error extracting key");
        }
        return true;
    }

    private PGPContentSignerBuilder getContentSignerBuilder(int hashAlgo, Map<ByteBuffer, byte[]> signedHashes) {
        if (isCompositeMlDsa65Ed25519()) {
            // Algorithm 30 has no upstream BC OpenPGP-level support (see
            // CompositeMlDsa65Ed25519's Javadoc) -- neither JcaPGPContentSignerBuilder (no JCA
            // algorithm-name mapping for it) nor NfcSyncPGPContentSignerBuilder (divert-to-card
            // secret keys are software-only for PQC, per the design's stated non-goal: no
            // OpenPGP card hardware does ML-DSA math on-card) can build a signer for it.
            if (mPrivateKeyState == PRIVATE_KEY_STATE_DIVERT_TO_CARD) {
                throw new UnsupportedOperationException(
                        "Composite ML-DSA-65+Ed25519 (algorithm 30) does not support divert-to-card "
                                + "signing; PQC secret keys are software-only.");
            }
            return new CompositeMlDsa65Ed25519ContentSignerBuilder(hashAlgo);
        } else if (mPrivateKeyState == PRIVATE_KEY_STATE_DIVERT_TO_CARD) {
            // use synchronous "NFC based" SignerBuilder
            return new NfcSyncPGPContentSignerBuilder(
                    mSecretKey.getPublicKey().getAlgorithm(), mSecretKey.getKeyID(),
                    true, hashAlgo, signedHashes)
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);
        } else {
            // content signer based on signing key algorithm and chosen hash algorithm
            return new JcaPGPContentSignerBuilder(
                    mSecretKey.getPublicKey().getAlgorithm(), hashAlgo)
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);
        }
    }

    /**
     * Builds a {@link PGPSignatureGenerator} whose signature version matches this key's own
     * public key packet version, per RFC9580's "version 6 keys MUST only generate version 6
     * signatures" rule (enforced by {@link PGPSignatureGenerator}'s own constructor). Classical
     * v4 keys are unaffected -- {@code signingKey.getVersion()} is 4 for those, exactly as the
     * previously-used single-argument (deprecated, hardcoded-v4) constructor produced. This
     * distinction only matters for algorithms that require v6 (currently: composite
     * ML-DSA-65+Ed25519, algorithm 30 -- see its Javadoc), which would otherwise fail signature
     * generation outright with a "Key version mismatch" PGPException.
     */
    private PGPSignatureGenerator newSignatureGenerator(PGPContentSignerBuilder contentSignerBuilder) {
        return new PGPSignatureGenerator(contentSignerBuilder, mSecretKey.getPublicKey());
    }

    public PGPSignatureGenerator getCertSignatureGenerator(Map<ByteBuffer, byte[]> signedHashes) {
        PGPContentSignerBuilder contentSignerBuilder = getContentSignerBuilder(
                PgpSecurityConstants.CERTIFY_HASH_ALGO, signedHashes);

        if (mPrivateKeyState == PRIVATE_KEY_STATE_LOCKED) {
            throw new PrivateKeyNotUnlockedException();
        }

        PGPSignatureGenerator signatureGenerator = newSignatureGenerator(contentSignerBuilder);
        try {
            signatureGenerator.init(PGPSignature.DEFAULT_CERTIFICATION, mPrivateKey);
            return signatureGenerator;
        } catch (PGPException e) {
            Timber.e(e, "signing error");
            return null;
        }
    }


    private PGPContentSignerBuilder getAuthenticationContentSignerBuilder(int hashAlgorithm, Map<ByteBuffer,
            byte[]> signedHashes) {
        if (getAlgorithm() == PublicKeyAlgorithmTags.EDDSA) {
            // content signer feeding the input directly into the signature engine,
            // no pre-hashing for EdDSA!
            if (mPrivateKeyState == PRIVATE_KEY_STATE_DIVERT_TO_CARD) {
                return new NfcSyncPGPContentSignerBuilder(
                        mSecretKey.getPublicKey().getAlgorithm(), mSecretKey.getKeyID(),
                        false, hashAlgorithm, signedHashes)
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);
            } else {
                return new EdDsaAuthenticationContentSignerBuilder(
                        mSecretKey.getPublicKey().getAlgorithm(), hashAlgorithm)
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);
            }
        } else {
            return getContentSignerBuilder(hashAlgorithm, signedHashes);
        }
    }

    public AuthenticationSignatureGenerator getAuthenticationSignatureGenerator(int hashAlgorithm,
                                                                                Map<ByteBuffer, byte[]> signedHashes)
            throws PgpGeneralException {
        if (mPrivateKeyState == PRIVATE_KEY_STATE_LOCKED) {
            throw new PrivateKeyNotUnlockedException();
        }

        PGPContentSignerBuilder contentSignerBuilder =
                getAuthenticationContentSignerBuilder(hashAlgorithm, signedHashes);

        try {
            AuthenticationSignatureGenerator signatureGenerator =
                    new AuthenticationSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, mPrivateKey);

            return signatureGenerator;
        } catch (PGPException e) {
            // TODO: simply throw PGPException!
            throw new PgpGeneralException("Error initializing signature!", e);
        }
    }

    public PGPSignatureGenerator getDataSignatureGenerator(int hashAlgo, boolean cleartext,
            Map<ByteBuffer, byte[]> signedHashes, Date creationTimestamp)
            throws PgpGeneralException {
        if (mPrivateKeyState == PRIVATE_KEY_STATE_LOCKED) {
            throw new PrivateKeyNotUnlockedException();
        }

        // We explicitly create a signature creation timestamp in this place.
        // That way, we can inject an artificial one from outside, ie the one
        // used in previous runs of this function.
        if (creationTimestamp == null) {
            // to sign using nfc PgpSignEncrypt is executed two times.
            // the first time it stops to return the PendingIntent for nfc connection and signing the hash
            // the second time the signed hash is used.
            // to get the same hash we cache the timestamp for the second round!
            creationTimestamp = new Date();
        }

        PGPContentSignerBuilder contentSignerBuilder = getContentSignerBuilder(hashAlgo, signedHashes);

        int signatureType;
        if (cleartext) {
            // for sign-only ascii text (cleartext signature)
            signatureType = PGPSignature.CANONICAL_TEXT_DOCUMENT;
        } else {
            signatureType = PGPSignature.BINARY_DOCUMENT;
        }

        try {
            PGPSignatureGenerator signatureGenerator = newSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(signatureType, mPrivateKey);

            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, mRing.getPrimaryUserIdWithFallback());
            spGen.setSignatureCreationTime(false, creationTimestamp);
            signatureGenerator.setHashedSubpackets(spGen.generate());
            return signatureGenerator;
        } catch (PGPException e) {
            // TODO: simply throw PGPException!
            throw new PgpGeneralException("Error initializing signature!", e);
        }
    }

    public CachingDataDecryptorFactory getCachingDecryptorFactory(CryptoInputParcel cryptoInput) {
        if (mPrivateKeyState == PRIVATE_KEY_STATE_LOCKED) {
            throw new PrivateKeyNotUnlockedException();
        }

        if (mPrivateKeyState == PRIVATE_KEY_STATE_DIVERT_TO_CARD) {
            return new CachingDataDecryptorFactory(
                    Constants.BOUNCY_CASTLE_PROVIDER_NAME,
                    cryptoInput.getCryptoData());
        } else if (isCompositeMlKem768X25519()) {
            // Algorithm 35 has no upstream BC support for the actual KEM math (see
            // CompositeMlKem768X25519's Javadoc) -- JcePublicKeyDataDecryptorFactoryBuilder's
            // own decryptor has no notion of this algorithm ID either, so we route it through
            // our own PublicKeyDataDecryptorFactory instead of BC's.
            return new CachingDataDecryptorFactory(
                    new CompositeMlKem768X25519PublicKeyDataDecryptorFactory(
                            this, Constants.BOUNCY_CASTLE_PROVIDER_NAME),
                    cryptoInput.getCryptoData());
        } else {
            return new CachingDataDecryptorFactory(
                    new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME).build(mPrivateKey),
                    cryptoInput.getCryptoData());
        }
    }

    /**
     * Returns true if this key uses the composite ML-KEM-768+X25519 encryption algorithm
     * (draft-ietf-openpgp-pqc-17, algorithm ID 35).
     */
    public boolean isCompositeMlKem768X25519() {
        return getAlgorithm() == PublicKeyAlgorithmTags.ML_KEM_768_X25519;
    }

    /**
     * Unwraps a PKESK's algorithm-specific data to recover the raw content-encryption
     * session key, using this key's composite ML-KEM-768+X25519 secret key material.
     * The key must already be {@link #unlock}ed.
     * <p>
     * This does not go through BC's usual {@code PGPSecretKey.extractPrivateKey} /
     * {@code JcePublicKeyDataDecryptorFactoryBuilder} machinery for the actual
     * decapsulation math -- both have hard-coded per-algorithm switches that don't know
     * about algorithm ID 35 either (confirmed by inspection of the vendored BC 1.84 fork;
     * only the *parsing/construction* of the surrounding packets was patched there, not
     * their crypto). The KEM decapsulation, KDF combiner, and key-unwrap all happen in
     * {@link CompositeMlKem768X25519}, called directly from here with the raw secret key
     * bytes obtained from the (already passphrase-unlocked) private key data packet.
     *
     * @param pkeskAlgorithmSpecificData the PKESK's algorithm-specific field bytes:
     *        {@code ecdhCipherText || mlkemCipherText || len || symAlgId || wrapped key}
     * @param expectedSessionKeyLength if positive, the recovered session key's length is
     *        checked against this value (the draft's mandated v3 PKESK length check)
     * @throws PgpGeneralException if this key isn't algorithm 35, isn't unlocked, or its
     *         secret key material isn't the expected 96-octet composite encoding
     * @throws InvalidCipherTextException if the RFC 3394 key-wrap integrity check fails
     *         (tampered PKESK data, or this is not the intended recipient key)
     */
    public byte[] decryptSessionKeyMlKem768X25519(byte[] pkeskAlgorithmSpecificData, int expectedSessionKeyLength)
            throws PgpGeneralException, InvalidCipherTextException {
        if (!isCompositeMlKem768X25519()) {
            throw new PgpGeneralException(
                    "Key algorithm " + getAlgorithm() + " is not composite ML-KEM-768+X25519 (35)!");
        }
        if (mPrivateKeyState != PRIVATE_KEY_STATE_UNLOCKED) {
            throw new PrivateKeyNotUnlockedException();
        }

        Object secretKeyDataPacket = mPrivateKey.getPrivateKeyDataPacket();
        if (!(secretKeyDataPacket instanceof OpaqueSecretBCPGKey)) {
            throw new PgpGeneralException("Expected opaque composite secret key material, got "
                    + secretKeyDataPacket.getClass().getName());
        }
        byte[] rawSecretKeyData = ((OpaqueSecretBCPGKey) secretKeyDataPacket).getEncoded();
        // BC's SecretKeyPacket format always appends a trailing checksum after the secret
        // key material proper for v4 keys (2 additive-checksum octets for USAGE_CHECKSUM,
        // 20 SHA-1 octets for USAGE_SHA1) -- this is true for every algorithm, not specific
        // to ours; the classical parsers (X25519SecretBCPGKey etc.) simply read their own
        // fixed-length prefix and never consume the trailer. Its integrity was already
        // verified generically by BC (in PGPSecretKey#extractKeyData) before this method
        // ever saw the bytes, for any key that was actually passphrase-protected; we only
        // need to take our own fixed-length prefix here, exactly like those classical
        // parsers do.
        if (rawSecretKeyData.length < CompositeMlKem768X25519.COMPOSITE_SECRET_KEY_LEN) {
            throw new PgpGeneralException("Composite secret key material is too short: "
                    + rawSecretKeyData.length);
        }
        byte[] compositeSecretKeyBytes = java.util.Arrays.copyOf(
                rawSecretKeyData, CompositeMlKem768X25519.COMPOSITE_SECRET_KEY_LEN);

        return CompositeMlKem768X25519.decryptSessionKey(
                compositeSecretKeyBytes, pkeskAlgorithmSpecificData, expectedSessionKeyLength);
    }

    // For use only in card export; returns the secret key in Chinese Remainder Theorem format.
    public RSAPrivateCrtKey getSecurityTokenRSASecretKey() throws PgpGeneralException {
        if (mPrivateKeyState == PRIVATE_KEY_STATE_LOCKED) {
            throw new PgpGeneralException("Cannot get secret key attributes while key is locked.");
        }

        if (mPrivateKeyState == PRIVATE_KEY_STATE_DIVERT_TO_CARD) {
            throw new PgpGeneralException("Cannot get secret key attributes of divert-to-card key.");
        }

        JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
        PrivateKey retVal;
        try {
            retVal = keyConverter.getPrivateKey(mPrivateKey);
        } catch (PGPException e) {
            throw new PgpGeneralException("Error converting private key!", e);
        }

        return (RSAPrivateCrtKey)retVal;
    }

    // For use only in card export; returns the secret key.
    public ECPrivateKey getSecurityTokenECSecretKey()
            throws PgpGeneralException {
        if (mPrivateKeyState == PRIVATE_KEY_STATE_LOCKED) {
            throw new PgpGeneralException("Cannot get secret key attributes while key is locked.");
        }

        if (mPrivateKeyState == PRIVATE_KEY_STATE_DIVERT_TO_CARD) {
            throw new PgpGeneralException("Cannot get secret key attributes of divert-to-card key.");
        }

        JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
        PrivateKey retVal;
        try {
            retVal = keyConverter.getPrivateKey(mPrivateKey);
        } catch (PGPException e) {
            throw new PgpGeneralException("Error converting private key! " + e.getMessage(), e);
        }

        return (ECPrivateKey) retVal;
    }

    public byte[] getIv() {
        return mSecretKey.getIV();
    }

    static class PrivateKeyNotUnlockedException extends RuntimeException {
        // this exception is a programming error which happens when an operation which requires
        // the private key is called without a previous call to unlock()
    }

    public UncachedSecretKey getUncached() {
        return new UncachedSecretKey(mSecretKey);
    }

    // HACK, for TESTING ONLY!!
    PGPPrivateKey getPrivateKey() {
        return mPrivateKey;
    }

    // HACK, for TESTING ONLY!!
    PGPSecretKey getSecretKey() {
        return mSecretKey;
    }

}
