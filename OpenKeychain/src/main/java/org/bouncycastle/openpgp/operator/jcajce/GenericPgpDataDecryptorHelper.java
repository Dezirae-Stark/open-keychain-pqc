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

package org.bouncycastle.openpgp.operator.jcajce;


import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;

/**
 * Exposes BC's package-private {@link OperatorHelper}/{@link JceAEADUtil} symmetric-decryptor
 * construction to other {@code PublicKeyDataDecryptorFactory} implementations that need it but
 * live outside this package -- namely {@code CompositeMlKem768X25519PublicKeyDataDecryptorFactory}
 * (in {@code org.sufficientlysecure.keychain.pgp.pqc}).
 * <p>
 * This class deliberately takes and returns only JDK/BC types (no {@code
 * org.sufficientlysecure.keychain.*} types) -- see this same package's {@link
 * CachingDataDecryptorFactory} for the established precedent of putting OpenKeychain-owned
 * files under {@code org.bouncycastle.*} purely to reach package-private BC helpers, and
 * critically why: unlike {@code CachingDataDecryptorFactory}, an earlier version of the
 * composite-KEM decryptor factory lived directly in this package and took a {@code
 * CanonicalizedSecretKey} constructor argument; under Robolectric's sandboxed class loader,
 * that produced a {@code LinkageError: loader constraint violation} at test time (this
 * package's classes and {@code org.sufficientlysecure.keychain.*} classes are, in practice,
 * resolved by different class loaders in that harness). Keeping this helper's surface free of
 * OpenKeychain types avoids that entirely, regardless of which class loader loads which
 * package under any given test/production runtime.
 */
public class GenericPgpDataDecryptorHelper {

    private final OperatorHelper mOperatorHelper;
    private final JceAEADUtil mAeadHelper;

    public GenericPgpDataDecryptorHelper(String providerName) {
        mOperatorHelper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        mAeadHelper = new JceAEADUtil(mOperatorHelper);
    }

    // OpenPGP v4
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
            throws PGPException {
        return mOperatorHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
    }

    // OpenPGP v5
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
            throws PGPException {
        return mAeadHelper.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    // OpenPGP v6
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
            throws PGPException {
        return mAeadHelper.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }
}
