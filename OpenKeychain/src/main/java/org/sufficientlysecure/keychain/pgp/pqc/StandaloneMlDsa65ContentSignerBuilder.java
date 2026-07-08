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
 * {@link PGPContentSignerBuilder} for standalone (non-composite, closed-ecosystem) ML-DSA-65
 * (OpenKeychain private-use algorithm ID 102, {@code EXPERIMENTAL_3}) signing. BC 1.84 has no
 * OpenPGP-level notion of this private-use algorithm at all (see {@link StandaloneMlDsa65}'s
 * Javadoc), so this routes signing through {@link StandaloneMlDsa65} directly -- the same
 * bypass-BC's-OpenPGP-object-model approach already used for {@link
 * SlhDsaShake128sContentSignerBuilder} and every composite ML-DSA content signer builder.
 *
 * <p>Computes the OpenPGP {@code dataDigest} itself (via a plain {@link MessageDigest}, since
 * BC's own JCA-based content signer machinery has no algorithm-name mapping for algorithm 102
 * either) and feeds it to {@link StandaloneMlDsa65#sign} once all streamed bytes have been
 * consumed -- structurally identical to {@link
 * CompositeMlDsa65Ed25519ContentSignerBuilder}, minus the Ed25519 half.
 */
public class StandaloneMlDsa65ContentSignerBuilder implements PGPContentSignerBuilder {

    private final int hashAlgorithm;
    private final SecureRandom random;

    public StandaloneMlDsa65ContentSignerBuilder(int hashAlgorithm) {
        this(hashAlgorithm, new SecureRandom());
    }

    public StandaloneMlDsa65ContentSignerBuilder(int hashAlgorithm, SecureRandom random) {
        this.hashAlgorithm = hashAlgorithm;
        this.random = random;
    }

    @Override
    public PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey) throws PGPException {
        if (privateKey.getPublicKeyPacket().getAlgorithm() != PublicKeyAlgorithmTags.EXPERIMENTAL_3) {
            throw new PGPException("Key algorithm " + privateKey.getPublicKeyPacket().getAlgorithm()
                    + " is not standalone ML-DSA-65 (102)!");
        }

        Object secretKeyDataPacket = privateKey.getPrivateKeyDataPacket();
        if (!(secretKeyDataPacket instanceof OpaqueSecretBCPGKey)) {
            throw new PGPException("Expected opaque standalone ML-DSA-65 secret key material, got "
                    + (secretKeyDataPacket == null ? "null" : secretKeyDataPacket.getClass().getName()));
        }
        byte[] rawSecretKeyData = ((OpaqueSecretBCPGKey) secretKeyDataPacket).getEncoded();
        if (rawSecretKeyData.length < StandaloneMlDsa65.SECRET_KEY_LEN) {
            throw new PGPException("Standalone ML-DSA-65 secret key material is too short: "
                    + rawSecretKeyData.length);
        }
        // As with the composite/SLH-DSA classes, any trailing checksum/S2K-integrity bytes a
        // v6 SecretKeyPacket may have appended are simply not part of our fixed-length prefix.
        final byte[] secretKeyBytes = Arrays.copyOf(rawSecretKeyData, StandaloneMlDsa65.SECRET_KEY_LEN);

        final String digestName = PGPUtil.getDigestName(hashAlgorithm);
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(digestName, Constants.BOUNCY_CASTLE_PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new PGPException("Cannot instantiate digest " + digestName + " for standalone ML-DSA-65 signing", e);
        }
        if (digest.getDigestLength() > 0 && digest.getDigestLength() < StandaloneMlDsa65.MIN_DATA_DIGEST_LEN) {
            // This codebase's own hygiene floor -- see StandaloneMlDsa65's class Javadoc. Fail
            // fast here rather than only at getSignature()/getDigest() time.
            throw new PGPException("Hash algorithm " + hashAlgorithm + " (" + digestName + ") produces a "
                    + (digest.getDigestLength() * 8) + "-bit digest, smaller than the 256-bit floor "
                    + "required for standalone ML-DSA-65 signing");
        }

        return new PGPContentSigner() {
            private byte[] cachedDigest;
            private byte[] cachedSignature;

            private byte[] computeDigest() throws PGPException {
                if (cachedDigest == null) {
                    cachedDigest = digest.digest();
                    if (cachedDigest.length < StandaloneMlDsa65.MIN_DATA_DIGEST_LEN) {
                        throw new PGPException("Hash algorithm " + hashAlgorithm + " (" + digestName
                                + ") produces a " + (cachedDigest.length * 8) + "-bit digest, smaller "
                                + "than the 256-bit floor required for standalone ML-DSA-65 signing");
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
                        cachedSignature = StandaloneMlDsa65.sign(secretKeyBytes, computeDigest(), random);
                    }
                    return cachedSignature;
                } catch (PGPException e) {
                    throw new org.bouncycastle.openpgp.PGPRuntimeOperationException(
                            "standalone ML-DSA-65 signing failed: " + e.getMessage(), e);
                }
            }

            @Override
            public byte[] getDigest() {
                try {
                    return computeDigest();
                } catch (PGPException e) {
                    throw new org.bouncycastle.openpgp.PGPRuntimeOperationException(
                            "standalone ML-DSA-65 digest computation failed: " + e.getMessage(), e);
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
                return PublicKeyAlgorithmTags.EXPERIMENTAL_3;
            }

            @Override
            public long getKeyID() {
                return privateKey.getKeyID();
            }
        };
    }
}
