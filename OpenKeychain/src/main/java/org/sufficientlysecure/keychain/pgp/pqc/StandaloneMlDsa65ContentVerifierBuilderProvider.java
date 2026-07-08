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

import org.bouncycastle.bcpg.OpaquePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.sufficientlysecure.keychain.Constants;

/**
 * {@link PGPContentVerifierBuilderProvider} for standalone ML-DSA-65 (OpenKeychain private-use
 * algorithm ID 102) signature verification -- the verification-side counterpart of {@link
 * StandaloneMlDsa65ContentSignerBuilder}. BC's own {@code JcaPGPContentVerifierBuilderProvider}
 * has no algorithm-name mapping for algorithm 102, so {@code PGPSignature#init}/{@code
 * PGPOnePassSignature#init} must be routed through this instead wherever the signing key turns
 * out to be algorithm 102 -- see {@code PgpSignatureChecker}'s two {@code initialize*} methods.
 */
public class StandaloneMlDsa65ContentVerifierBuilderProvider implements PGPContentVerifierBuilderProvider {

    @Override
    public PGPContentVerifierBuilder get(final int keyAlgorithm, final int hashAlgorithm) throws PGPException {
        if (keyAlgorithm != PublicKeyAlgorithmTags.EXPERIMENTAL_3) {
            throw new PGPException("Key algorithm " + keyAlgorithm + " is not standalone ML-DSA-65 (102)!");
        }

        return new PGPContentVerifierBuilder() {
            @Override
            public PGPContentVerifier build(final PGPPublicKey publicKey) throws PGPException {
                Object key = publicKey.getPublicKeyPacket().getKey();
                if (!(key instanceof OpaquePublicBCPGKey)) {
                    throw new PGPException("Expected opaque standalone ML-DSA-65 public key material, got "
                            + (key == null ? "null" : key.getClass().getName()));
                }
                byte[] publicKeyBytes = ((OpaquePublicBCPGKey) key).getEncoded();
                if (publicKeyBytes.length != StandaloneMlDsa65.PUBLIC_KEY_LEN) {
                    throw new PGPException("Standalone ML-DSA-65 public key material has unexpected length: "
                            + publicKeyBytes.length);
                }

                final String digestName = PGPUtil.getDigestName(hashAlgorithm);
                final MessageDigest digest;
                try {
                    digest = MessageDigest.getInstance(digestName, Constants.BOUNCY_CASTLE_PROVIDER_NAME);
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    throw new PGPException("Cannot instantiate digest " + digestName + " for standalone ML-DSA-65 verification", e);
                }

                return new PGPContentVerifier() {
                    @Override
                    public int getHashAlgorithm() {
                        return hashAlgorithm;
                    }

                    @Override
                    public int getKeyAlgorithm() {
                        return keyAlgorithm;
                    }

                    @Override
                    public long getKeyID() {
                        return publicKey.getKeyID();
                    }

                    @Override
                    public boolean verify(byte[] expected) {
                        byte[] dataDigest = digest.digest();
                        if (dataDigest.length < StandaloneMlDsa65.MIN_DATA_DIGEST_LEN) {
                            // This codebase's own hygiene floor -- see StandaloneMlDsa65's
                            // class Javadoc.
                            return false;
                        }
                        if (expected.length != StandaloneMlDsa65.SIGNATURE_LEN) {
                            return false;
                        }
                        return StandaloneMlDsa65.verify(publicKeyBytes, dataDigest, expected);
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
                };
            }
        };
    }
}
