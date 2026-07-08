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


import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.GenericPgpDataDecryptorHelper;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;

/**
 * Routes real-app OpenPGP decryption (via {@code PgpDecryptVerifyOperation} ->
 * {@code PGPPublicKeyEncryptedData.getSessionKey()}/{@code getDataStream()}) through {@link
 * CanonicalizedSecretKey#decryptSessionKeyMlKem1024X448} for algorithm 36 (composite
 * ML-KEM-1024+X448) keys. Mirrors {@link CompositeMlKem768X25519PublicKeyDataDecryptorFactory}
 * exactly -- see that class's Javadoc for the session-info-framing rationale, which applies
 * identically here.
 */
public class CompositeMlKem1024X448PublicKeyDataDecryptorFactory extends AbstractPublicKeyDataDecryptorFactory {

    private final CanonicalizedSecretKey mSecretKey;
    private final GenericPgpDataDecryptorHelper mDecryptorHelper;

    public CompositeMlKem1024X448PublicKeyDataDecryptorFactory(CanonicalizedSecretKey secretKey, String providerName) {
        mSecretKey = secretKey;
        mDecryptorHelper = new GenericPgpDataDecryptorHelper(providerName);
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion) throws PGPException {
        byte[] algorithmSpecificData = secKeyData[0];
        byte[] rawSessionKey;
        try {
            // expectedSessionKeyLength 0: we don't know the session key length ahead of
            // decryption here: the generic confirmCheckSum() call BC makes on our returned,
            // fully-framed session info is what actually validates the recovered data.
            rawSessionKey = mSecretKey.decryptSessionKeyMlKem1024X448(algorithmSpecificData, 0);
        } catch (PgpGeneralException e) {
            throw new PGPException(
                    "Error decrypting session key with composite ML-KEM-1024+X448 key: " + e.getMessage(), e);
        } catch (InvalidCipherTextException e) {
            throw new PGPException("Composite ML-KEM-1024+X448 key-wrap integrity check failed: "
                    + e.getMessage(), e);
        }

        int symAlgId = CompositeMlKem1024X448.extractPlaintextSymAlgId(algorithmSpecificData);

        // classical [symAlgId][sessionKey][checksum] framing, as PGPPublicKeyEncryptedData's
        // containsChecksum()/confirmCheckSum() require for any algorithm ID other than
        // X25519/X448 (see class Javadoc).
        byte[] sessionInfo = new byte[1 + rawSessionKey.length + 2];
        sessionInfo[0] = (byte) symAlgId;
        System.arraycopy(rawSessionKey, 0, sessionInfo, 1, rawSessionKey.length);
        addCheckSum(sessionInfo);
        return sessionInfo;
    }

    private static void addCheckSum(byte[] sessionInfo) {
        int check = 0;
        for (int i = 1; i != sessionInfo.length - 2; i++) {
            check += sessionInfo[i] & 0xff;
        }
        sessionInfo[sessionInfo.length - 2] = (byte) (check >> 8);
        sessionInfo[sessionInfo.length - 1] = (byte) check;
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
            throws PGPException {
        return mDecryptorHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
            throws PGPException {
        return mDecryptorHelper.createDataDecryptor(aeadEncDataPacket, sessionKey);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
            throws PGPException {
        return mDecryptorHelper.createDataDecryptor(seipd, sessionKey);
    }
}
