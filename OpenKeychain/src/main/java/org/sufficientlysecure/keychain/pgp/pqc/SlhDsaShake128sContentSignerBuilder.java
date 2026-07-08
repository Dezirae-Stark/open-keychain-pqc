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

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.bcpg.OpaqueSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.sufficientlysecure.keychain.Constants;

/**
 * {@link PGPContentSignerBuilder} for standalone SLH-DSA-SHAKE-128s (draft-ietf-openpgp-pqc-17,
 * algorithm ID 32) signing. BC 1.84 has no OpenPGP-level notion of this algorithm at all (see
 * {@link SlhDsaShake128s}'s Javadoc), so unlike the classical algorithms {@code
 * CanonicalizedSecretKey} otherwise builds a {@code JcaPGPContentSignerBuilder} for, this routes
 * signing through {@link SlhDsaShake128s} directly -- the same bypass-BC's-OpenPGP-object-model
 * approach already used for the composite ML-DSA signing classes.
 *
 * <p>Per the draft, the SLH-DSA signature covers the same OpenPGP {@code dataDigest} the
 * composite algorithms sign -- the hash, using the signature packet's declared hash algorithm,
 * of everything {@link org.bouncycastle.openpgp.PGPSignatureGenerator} streams through {@link
 * PGPContentSigner#getOutputStream()} (the v6 salt, the signed content, and the signature
 * trailer, in that order -- see RFC9580 §5.2.4). This class computes that same digest itself
 * (via a plain {@link MessageDigest}, since BC's own JCA-based content signer machinery has no
 * algorithm-name mapping for algorithm 32 either) and feeds it to {@link SlhDsaShake128s#sign}
 * once all streamed bytes have been consumed.
 */
public class SlhDsaShake128sContentSignerBuilder implements PGPContentSignerBuilder {

    private final int hashAlgorithm;
    private final SecureRandom random;

    public SlhDsaShake128sContentSignerBuilder(int hashAlgorithm) {
        this(hashAlgorithm, new SecureRandom());
    }

    public SlhDsaShake128sContentSignerBuilder(int hashAlgorithm, SecureRandom random) {
        this.hashAlgorithm = hashAlgorithm;
        this.random = random;
    }

    @Override
    public PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey) throws PGPException {
        if (privateKey.getPublicKeyPacket().getAlgorithm() != PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S) {
            throw new PGPException("Key algorithm " + privateKey.getPublicKeyPacket().getAlgorithm()
                    + " is not SLH-DSA-SHAKE-128s (32)!");
        }

        Object secretKeyDataPacket = privateKey.getPrivateKeyDataPacket();
        if (!(secretKeyDataPacket instanceof OpaqueSecretBCPGKey)) {
            throw new PGPException("Expected opaque SLH-DSA secret key material, got "
                    + (secretKeyDataPacket == null ? "null" : secretKeyDataPacket.getClass().getName()));
        }
        byte[] rawSecretKeyData = ((OpaqueSecretBCPGKey) secretKeyDataPacket).getEncoded();
        if (rawSecretKeyData.length < SlhDsaShake128s.SECRET_KEY_LEN) {
            throw new PGPException("SLH-DSA-SHAKE-128s secret key material is too short: "
                    + rawSecretKeyData.length);
        }
        // As with the composite ML-DSA classes, any trailing checksum/S2K-integrity bytes a v6
        // SecretKeyPacket may have appended are simply not part of our fixed-length prefix --
        // take exactly that prefix.
        final byte[] secretKeyBytes = Arrays.copyOf(rawSecretKeyData, SlhDsaShake128s.SECRET_KEY_LEN);

        final String digestName = PGPUtil.getDigestName(hashAlgorithm);
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(digestName, Constants.BOUNCY_CASTLE_PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new PGPException("Cannot instantiate digest " + digestName + " for SLH-DSA signing", e);
        }
        if (digest.getDigestLength() > 0 && digest.getDigestLength() < SlhDsaShake128s.MIN_DATA_DIGEST_LEN) {
            // draft-ietf-openpgp-pqc-17: "An SLH-DSA signature MUST use a hash algorithm with a
            // digest size of at least 256 bits." Fail fast here rather than only at
            // getSignature()/getDigest() time.
            throw new PGPException("Hash algorithm " + hashAlgorithm + " (" + digestName + ") produces a "
                    + (digest.getDigestLength() * 8) + "-bit digest, smaller than the 256-bit floor "
                    + "required for SLH-DSA signing");
        }

        return new PGPContentSigner() {
            private byte[] cachedDigest;
            private byte[] cachedSignature;

            private byte[] computeDigest() throws PGPException {
                if (cachedDigest == null) {
                    cachedDigest = digest.digest();
                    if (cachedDigest.length < SlhDsaShake128s.MIN_DATA_DIGEST_LEN) {
                        // draft-ietf-openpgp-pqc-17: "An SLH-DSA signature MUST use a hash
                        // algorithm with a digest size of at least 256 bits."
                        throw new PGPException("Hash algorithm " + hashAlgorithm + " (" + digestName
                                + ") produces a " + (cachedDigest.length * 8) + "-bit digest, smaller "
                                + "than the 256-bit floor required for SLH-DSA signing");
                    }
                }
                return cachedDigest;
            }

            @Override
            public OutputStream getOutputStream() {
                return new OutputStream() {
                    @Override
                    public void write(int b) {
                        digest.update((byte) b);
                    }

                    @Override
                    public void write(byte[] b, int off, int len) {
                        digest.update(b, off, len);
                    }
                };
            }

            @Override
            public byte[] getSignature() {
                try {
                    if (cachedSignature == null) {
                        cachedSignature = SlhDsaShake128s.sign(secretKeyBytes, computeDigest(), random);
                    }
                    return cachedSignature;
                } catch (PGPException e) {
                    throw new org.bouncycastle.openpgp.PGPRuntimeOperationException(
                            "SLH-DSA-SHAKE-128s signing failed: " + e.getMessage(), e);
                }
            }

            @Override
            public byte[] getDigest() {
                try {
                    return computeDigest();
                } catch (PGPException e) {
                    throw new org.bouncycastle.openpgp.PGPRuntimeOperationException(
                            "SLH-DSA-SHAKE-128s digest computation failed: " + e.getMessage(), e);
                }
            }

            @Override
            public int getType() {
                return signatureType;
            }

            @Override
            public int getHashAlgorithm() {
                return hashAlgorithm;
            }

            @Override
            public int getKeyAlgorithm() {
                return PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S;
            }

            @Override
            public long getKeyID() {
                return privateKey.getKeyID();
            }
        };
    }
}
