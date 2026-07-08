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
 * CanonicalizedSecretKey#decryptSessionKeyMlKem768X25519} for algorithm 35 (composite
 * ML-KEM-768+X25519) keys.
 * <p>
 * The actual (algorithm-35-agnostic) symmetric decryption once the session key has been
 * recovered is delegated to {@link GenericPgpDataDecryptorHelper}, which reaches BC's
 * package-private {@code OperatorHelper}/{@code JceAEADUtil} helpers from the {@code
 * org.bouncycastle.openpgp.operator.jcajce} package on our behalf -- see that class's Javadoc
 * for why this class deliberately does *not* live in that package itself (a Robolectric
 * class-loader constraint, not a production concern, but real regardless).
 * <p>
 * <b>Session-info framing</b>: BC's {@code PGPPublicKeyEncryptedData} only skips the
 * classical {@code [symAlgId][sessionKey][checksum]} framing for algorithm IDs it
 * special-cases as "no checksum" (X25519, X448 -- see {@code
 * AbstractPublicKeyDataDecryptorFactory#prependSKAlgorithmToSessionData} and {@code
 * PGPPublicKeyEncryptedData#containsChecksum}). Algorithm 35 isn't special-cased there, so
 * this class must reconstruct that framing itself: it recovers the raw session key from
 * {@link CompositeMlKem768X25519} (which, like the X25519/X448 wire format, carries no
 * checksum of its own -- RFC 3394 key wrap has its own 64-bit integrity check instead),
 * reads the plaintext symAlgId directly off the PKESK's algorithm-specific bytes via {@link
 * CompositeMlKem768X25519#extractPlaintextSymAlgId}, and appends the classical two-octet
 * additive checksum so the generic BC code's {@code confirmCheckSum} call succeeds.
 */
public class CompositeMlKem768X25519PublicKeyDataDecryptorFactory extends AbstractPublicKeyDataDecryptorFactory {

    private final CanonicalizedSecretKey mSecretKey;
    private final GenericPgpDataDecryptorHelper mDecryptorHelper;

    public CompositeMlKem768X25519PublicKeyDataDecryptorFactory(CanonicalizedSecretKey secretKey, String providerName) {
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
            rawSessionKey = mSecretKey.decryptSessionKeyMlKem768X25519(algorithmSpecificData, 0);
        } catch (PgpGeneralException e) {
            throw new PGPException(
                    "Error decrypting session key with composite ML-KEM-768+X25519 key: " + e.getMessage(), e);
        } catch (InvalidCipherTextException e) {
            throw new PGPException("Composite ML-KEM-768+X25519 key-wrap integrity check failed: "
                    + e.getMessage(), e);
        }

        int symAlgId = CompositeMlKem768X25519.extractPlaintextSymAlgId(algorithmSpecificData);

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
