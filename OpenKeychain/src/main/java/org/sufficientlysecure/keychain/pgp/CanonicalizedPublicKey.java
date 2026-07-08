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


import java.io.IOException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.OpaquePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlKem1024X448;
import org.sufficientlysecure.keychain.pgp.pqc.CompositeMlKem768X25519;
import org.sufficientlysecure.keychain.util.IterableIterator;
import timber.log.Timber;

/** Wrapper for a PGPPublicKey.
 *
 * The methods implemented in this class are a thin layer over
 * UncachedPublicKey. The difference between the two classes is that objects of
 * this class can only be obtained from a WrappedKeyRing, and that it stores a
 * back reference to its parent as well. A method which works with
 * WrappedPublicKey is therefore guaranteed to work on a KeyRing which is
 * stored in the database.
 *
 */
public class CanonicalizedPublicKey extends UncachedPublicKey {

    // this is the parent key ring
    final CanonicalizedKeyRing mRing;

    CanonicalizedPublicKey(CanonicalizedKeyRing ring, PGPPublicKey key) {
        super(key);
        mRing = ring;
    }

    public CanonicalizedKeyRing getKeyRing() {
        return mRing;
    }

    public IterableIterator<String> getUserIds() {
        return new IterableIterator<String>(mPublicKey.getUserIDs());
    }

    PGPKeyEncryptionMethodGenerator getPubKeyEncryptionGenerator(boolean hiddenRecipients) {
        // Algorithm 35 (composite ML-KEM-768+X25519) has no upstream BC support for the
        // actual KEM math (see CompositeMlKem768X25519's Javadoc) -- JcePublicKeyKeyEncryptionMethodGenerator's
        // own constructor would reject this algorithm ID outright (unknown to its switch),
        // so we route it through our own PGPKeyEncryptionMethodGenerator instead of BC's.
        if (isCompositeMlKem768X25519()) {
            return new CompositeMlKem768X25519KeyEncryptionMethodGenerator(this);
        }
        // Same rationale as algorithm 35 above, for composite ML-KEM-1024+X448 (algorithm 36).
        if (isCompositeMlKem1024X448()) {
            return new CompositeMlKem1024X448KeyEncryptionMethodGenerator(this);
        }

        JcePublicKeyKeyEncryptionMethodGenerator generator =
                new JcePublicKeyKeyEncryptionMethodGenerator(mPublicKey);
        generator.setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);
        generator.setSessionKeyObfuscation(hiddenRecipients);
        return generator;
    }

    /**
     * Routes real-app OpenPGP encryption (via {@code PgpSignEncryptOperation} ->
     * {@code PGPEncryptedDataGenerator.addMethod()}) through {@link
     * #encryptSessionKeyMlKem768X25519} for algorithm 35 keys, producing a v3 PKESK packet
     * whose algorithm-specific data is exactly what that method returns. This is the
     * plugging-in point the composite crypto core needed but never had: without it, {@link
     * CanonicalizedPublicKey}'s composite encrypt method was only ever reachable from tests
     * that called it directly, never from a real encrypt operation.
     */
    private static final class CompositeMlKem768X25519KeyEncryptionMethodGenerator
            implements PGPKeyEncryptionMethodGenerator {

        private final CanonicalizedPublicKey mKey;
        private final long mKeyId;

        CompositeMlKem768X25519KeyEncryptionMethodGenerator(CanonicalizedPublicKey key) {
            mKey = key;
            mKeyId = key.getKeyId();
        }

        @Override
        public ContainedPacket generate(PGPDataEncryptorBuilder dataEncryptorBuilder, byte[] sessionKey)
                throws PGPException {
            // dataEncryptorBuilder.getAlgorithm() is the plaintext v3-PKESK symmetric
            // algorithm ID; sessionKey here is the raw (unframed) content-encryption key --
            // PGPEncryptedDataGenerator.open() passes it exactly this way for every public-key
            // method (compare to how it treats X25519/X448 the same way, no [algo][key]
            // [checksum] framing applied before this call for any of these).
            try {
                byte[] algorithmSpecificData = mKey.encryptSessionKeyMlKem768X25519(
                        dataEncryptorBuilder.getAlgorithm(), sessionKey);
                return PublicKeyEncSessionPacket.createV3PKESKPacket(
                        mKeyId, PublicKeyAlgorithmTags.ML_KEM_768_X25519,
                        new byte[][] { algorithmSpecificData });
            } catch (PgpGeneralException e) {
                throw new PGPException(
                        "Error encrypting session key with composite ML-KEM-768+X25519 key: "
                                + e.getMessage(), e);
            }
        }
    }

    /**
     * Routes real-app OpenPGP encryption through {@link #encryptSessionKeyMlKem1024X448} for
     * algorithm 36 keys. Mirrors {@link CompositeMlKem768X25519KeyEncryptionMethodGenerator}
     * exactly -- see that class's Javadoc for the rationale.
     */
    private static final class CompositeMlKem1024X448KeyEncryptionMethodGenerator
            implements PGPKeyEncryptionMethodGenerator {

        private final CanonicalizedPublicKey mKey;
        private final long mKeyId;

        CompositeMlKem1024X448KeyEncryptionMethodGenerator(CanonicalizedPublicKey key) {
            mKey = key;
            mKeyId = key.getKeyId();
        }

        @Override
        public ContainedPacket generate(PGPDataEncryptorBuilder dataEncryptorBuilder, byte[] sessionKey)
                throws PGPException {
            try {
                byte[] algorithmSpecificData = mKey.encryptSessionKeyMlKem1024X448(
                        dataEncryptorBuilder.getAlgorithm(), sessionKey);
                return PublicKeyEncSessionPacket.createV3PKESKPacket(
                        mKeyId, PublicKeyAlgorithmTags.ML_KEM_1024_X448,
                        new byte[][] { algorithmSpecificData });
            } catch (PgpGeneralException e) {
                throw new PGPException(
                        "Error encrypting session key with composite ML-KEM-1024+X448 key: "
                                + e.getMessage(), e);
            }
        }
    }

    public boolean canSign() {
        // if key flags subpacket is available, honor it!
        if (getKeyUsage() != 0) {
            return (getKeyUsage() & KeyFlags.SIGN_DATA) != 0;
        }

        if (UncachedKeyRing.isSigningAlgo(mPublicKey.getAlgorithm())) {
            return true;
        }

        return false;
    }

    public boolean canCertify() {
        if (!isMasterKey()) {
            return false;
        }

        // if key flags subpacket is available, honor it!
        if (getKeyUsage() != 0) {
            return (getKeyUsage() & KeyFlags.CERTIFY_OTHER) != 0;
        }

        if (UncachedKeyRing.isSigningAlgo(mPublicKey.getAlgorithm())) {
            return true;
        }

        return false;
    }

    public boolean canEncrypt() {
        // if key flags subpacket is available, honor it!
        if (getKeyUsage() != 0) {
            return (getKeyUsage() & (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE)) != 0;
        }

        // RSA_GENERAL, RSA_ENCRYPT, ELGAMAL_ENCRYPT, ELGAMAL_GENERAL, ECDH
        if (UncachedKeyRing.isEncryptionAlgo(mPublicKey.getAlgorithm())) {
            return true;
        }

        return false;
    }

    public boolean canAuthenticate() {
        // if key flags subpacket is available, honor it!
        if (getKeyUsage() != 0) {
            return (getKeyUsage() & KeyFlags.AUTHENTICATION) != 0;
        }

        return false;
    }

    public boolean isRevoked() {
        return mPublicKey.getSignaturesOfType(isMasterKey()
                ? PGPSignature.KEY_REVOCATION
                : PGPSignature.SUBKEY_REVOCATION).hasNext();
    }

    public boolean isExpired() {
        Date expiry = getExpiryTime();
        return expiry != null && expiry.before(new Date());
    }

    private boolean hasFutureSigningDate() {
        if (isMasterKey()) {
            return false;
        }

        WrappedSignature subkeyBindingSignature = getSubkeyBindingSignature();
        return subkeyBindingSignature.getCreationTime().after(new Date());
    }

    private WrappedSignature getSubkeyBindingSignature() {
        Iterator subkeyBindingSignatures = mPublicKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
        PGPSignature singleSubkeyBindingsignature = (PGPSignature) subkeyBindingSignatures.next();
        if (subkeyBindingSignatures.hasNext()) {
            throw new IllegalStateException();
        }
        return new WrappedSignature(singleSubkeyBindingsignature);
    }

    public Date getBindingSignatureTime() {
        return isMasterKey() ? getCreationTime() : getSubkeyBindingSignature().getCreationTime();
    }

    public boolean isSecure() {
        return PgpSecurityConstants.checkForSecurityProblems(this) == null;
    }

    public long getValidSeconds() {

        long seconds;

        // the getValidSeconds method is unreliable for master keys. we need to iterate all
        // user ids, then use the most recent certification from a non-revoked user id
        if (isMasterKey()) {
            seconds = 0;

            long masterKeyId = getKeyId();

            Date latestCreation = null;
            for (byte[] rawUserId : getUnorderedRawUserIds()) {
                Iterator<WrappedSignature> sigs = getSignaturesForRawId(rawUserId);
                while (sigs.hasNext()) {
                    WrappedSignature sig = sigs.next();
                    if (sig.getKeyId() != masterKeyId) {
                        continue;
                    }
                    if (sig.isRevocation()) {
                        continue;
                    }

                    if (latestCreation == null || latestCreation.before(sig.getCreationTime())) {
                        latestCreation = sig.getCreationTime();
                        seconds = sig.getKeyExpirySeconds();
                    }

                }
            }
        } else {
            seconds = mPublicKey.getValidSeconds();
        }

        return seconds;
    }

    public Date getExpiryTime() {
        long seconds = getValidSeconds();

        if (seconds > Integer.MAX_VALUE) {
            Timber.e("error, expiry time too large");
            return null;
        }
        if (seconds == 0) {
            // no expiry
            return null;
        }
        Date creationDate = getCreationTime();
        Calendar calendar = GregorianCalendar.getInstance();
        calendar.setTime(creationDate);
        calendar.add(Calendar.SECOND, (int) seconds);

        return calendar.getTime();
    }

    /** Same method as superclass, but we make it public. */
    public Integer getKeyUsage() {
        return super.getKeyUsage();
    }

    /** Returns whether this key is valid, ie not expired or revoked. */
    public boolean isValid() {
        return !isRevoked() && !isExpired() && !hasFutureSigningDate();
    }

    // For use in key export only; returns the public key in a JCA compatible format.
    public PublicKey getJcaPublicKey() throws PgpGeneralException {
        JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
        PublicKey publicKey;
        try {
            publicKey = keyConverter.getPublicKey(mPublicKey);
        } catch (PGPException e) {
            throw new PgpGeneralException("Error converting public key: "+ e.getMessage(), e);
        }
        return publicKey;
    }

    // For use in card export only; returns the public key in a JCA compatible format.
    public ECPublicKey getSecurityTokenECPublicKey()
            throws PgpGeneralException {
        return (ECPublicKey) getJcaPublicKey();
    }

    public ASN1ObjectIdentifier getSecurityTokenHashAlgorithm()
            throws PGPException {
        if (!isEC()) {
            throw new PGPException("Key encryption OID is valid only for EC key!");
        }

        final ECDHPublicBCPGKey eck = (ECDHPublicBCPGKey)mPublicKey.getPublicKeyPacket().getKey();

        switch (eck.getHashAlgorithm()) {
            case HashAlgorithmTags.SHA256:
                return NISTObjectIdentifiers.id_sha256;
            case HashAlgorithmTags.SHA384:
                return NISTObjectIdentifiers.id_sha384;
            case HashAlgorithmTags.SHA512:
                return NISTObjectIdentifiers.id_sha512;
            default:
                throw new PGPException("Invalid hash algorithm for EC key : " + eck.getHashAlgorithm());
        }
    }

    public int getSecurityTokenSymmetricKeySize()
            throws PGPException {
        if (!isEC()) {
            throw new PGPException("Key encryption OID is valid only for EC key!");
        }

        final ECDHPublicBCPGKey eck = (ECDHPublicBCPGKey)mPublicKey.getPublicKeyPacket().getKey();

        switch (eck.getSymmetricKeyAlgorithm()) {
            case SymmetricKeyAlgorithmTags.AES_128:
                return 128;
            case SymmetricKeyAlgorithmTags.AES_192:
                return 192;
            case SymmetricKeyAlgorithmTags.AES_256:
                return 256;
            default:
                throw new PGPException("Invalid symmetric encryption algorithm for EC key : " + eck.getSymmetricKeyAlgorithm());
        }
    }

    public byte[] createUserKeyingMaterial(KeyFingerPrintCalculator fingerPrintCalculator)
            throws IOException, PGPException {
        return RFC6637Utils.createUserKeyingMaterial(mPublicKey.getPublicKeyPacket(), fingerPrintCalculator);
    }

    /**
     * Returns true if this key uses the composite ML-KEM-768+X25519 encryption algorithm
     * (draft-ietf-openpgp-pqc-17, algorithm ID 35).
     */
    public boolean isCompositeMlKem768X25519() {
        return getAlgorithm() == PublicKeyAlgorithmTags.ML_KEM_768_X25519;
    }

    /**
     * Returns true if this key uses the composite ML-KEM-1024+X448 encryption algorithm
     * (draft-ietf-openpgp-pqc-17, algorithm ID 36).
     */
    public boolean isCompositeMlKem1024X448() {
        return getAlgorithm() == PublicKeyAlgorithmTags.ML_KEM_1024_X448;
    }

    /**
     * Returns true if this key uses the composite ML-DSA-65+Ed25519 signing algorithm
     * (draft-ietf-openpgp-pqc-17, algorithm ID 30).
     */
    public boolean isCompositeMlDsa65Ed25519() {
        return getAlgorithm() == PublicKeyAlgorithmTags.ML_DSA_65_Ed25519;
    }

    /**
     * Returns true if this key uses the composite ML-DSA-87+Ed448 signing algorithm
     * (draft-ietf-openpgp-pqc-17, algorithm ID 31).
     */
    public boolean isCompositeMlDsa87Ed448() {
        return getAlgorithm() == PublicKeyAlgorithmTags.ML_DSA_87_Ed448;
    }

    /**
     * Wraps a raw content-encryption session key to this key's composite ML-KEM-768+X25519
     * public key, producing the v3 PKESK (Public-Key Encrypted Session Key, packet type 1)
     * algorithm-specific field bytes defined by draft-ietf-openpgp-pqc-17 -- see {@link
     * CompositeMlKem768X25519}'s Javadoc for the exact wire layout and what in this class'
     * behavior was verified against the fetched spec text vs. independently hand-derived.
     *
     * @param symmetricAlgorithmId the plaintext (v3 PKESK) symmetric algorithm ID under
     *                             which {@code sessionKey} will be used
     * @param sessionKey the raw content-encryption key octets
     * @throws PgpGeneralException if this key does not use algorithm ID 35, or its public
     *         key material is not the expected 1216-octet composite encoding
     */
    public byte[] encryptSessionKeyMlKem768X25519(int symmetricAlgorithmId, byte[] sessionKey)
            throws PgpGeneralException {
        if (!isCompositeMlKem768X25519()) {
            throw new PgpGeneralException(
                    "Key algorithm " + getAlgorithm() + " is not composite ML-KEM-768+X25519 (35)!");
        }

        byte[] compositePublicKeyBytes = getOpaquePublicKeyMaterial();
        if (compositePublicKeyBytes.length != CompositeMlKem768X25519.COMPOSITE_PUBLIC_KEY_LEN) {
            throw new PgpGeneralException("Composite public key material has unexpected length: "
                    + compositePublicKeyBytes.length);
        }

        return CompositeMlKem768X25519.encryptSessionKey(
                compositePublicKeyBytes, (byte) symmetricAlgorithmId, sessionKey, new SecureRandom());
    }

    /**
     * Wraps a raw content-encryption session key to this key's composite ML-KEM-1024+X448
     * public key, producing the v3 PKESK algorithm-specific field bytes defined by
     * draft-ietf-openpgp-pqc-17 -- see {@link CompositeMlKem1024X448}'s Javadoc for the exact
     * wire layout. Mirrors {@link #encryptSessionKeyMlKem768X25519} exactly.
     *
     * @param symmetricAlgorithmId the plaintext (v3 PKESK) symmetric algorithm ID under
     *                             which {@code sessionKey} will be used
     * @param sessionKey the raw content-encryption key octets
     * @throws PgpGeneralException if this key does not use algorithm ID 36, or its public
     *         key material is not the expected 1624-octet composite encoding
     */
    public byte[] encryptSessionKeyMlKem1024X448(int symmetricAlgorithmId, byte[] sessionKey)
            throws PgpGeneralException {
        if (!isCompositeMlKem1024X448()) {
            throw new PgpGeneralException(
                    "Key algorithm " + getAlgorithm() + " is not composite ML-KEM-1024+X448 (36)!");
        }

        byte[] compositePublicKeyBytes = getOpaquePublicKeyMaterial();
        if (compositePublicKeyBytes.length != CompositeMlKem1024X448.COMPOSITE_PUBLIC_KEY_LEN) {
            throw new PgpGeneralException("Composite public key material has unexpected length: "
                    + compositePublicKeyBytes.length);
        }

        return CompositeMlKem1024X448.encryptSessionKey(
                compositePublicKeyBytes, (byte) symmetricAlgorithmId, sessionKey, new SecureRandom());
    }

    /**
     * Returns the raw composite (ECDH public key || ML-KEM public key) bytes for this key's
     * public key packet, as parsed generically by BC's {@code OpaquePublicBCPGKey} (BC 1.84
     * does not structurally recognize algorithm ID 35 -- see the OpenKeychain patch
     * comments on {@code PublicKeyPacket}'s default case in the vendored
     * extern/bouncycastle fork).
     */
    byte[] getOpaquePublicKeyMaterial() throws PgpGeneralException {
        Object key = mPublicKey.getPublicKeyPacket().getKey();
        if (!(key instanceof OpaquePublicBCPGKey)) {
            throw new PgpGeneralException(
                    "Expected opaque composite public key material, got " + key.getClass().getName());
        }
        return ((OpaquePublicBCPGKey) key).getEncoded();
    }
}
