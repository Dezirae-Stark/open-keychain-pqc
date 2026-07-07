/*
 * Copyright (c) 2013-2014 Philipp Jakubeit, Signe Rüsch, Dominik Schürmann
 * Copyright (c) 2017 Vincent Breitmoser
 *
 * Licensed under the Bouncy Castle License (MIT license). See LICENSE file for details.
 */

package org.bouncycastle.openpgp.operator.jcajce;


import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;


public class CachingDataDecryptorFactory extends AbstractPublicKeyDataDecryptorFactory
{
    private final PublicKeyDataDecryptorFactory mWrappedDecryptor;
    private final HashMap<ByteBuffer, byte[]> mSessionKeyCache;

    private OperatorHelper mOperatorHelper;
    private JceAEADUtil mAeadHelper;

    public CachingDataDecryptorFactory(String providerName, Map<ByteBuffer, byte[]> sessionKeyCache)
    {
        this((PublicKeyDataDecryptorFactory) null, sessionKeyCache);

        mOperatorHelper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        mAeadHelper = new JceAEADUtil(mOperatorHelper);
    }

    public CachingDataDecryptorFactory(PublicKeyDataDecryptorFactory wrapped,
            Map<ByteBuffer, byte[]> sessionKeyCache)
    {
        mSessionKeyCache = new HashMap<>();
        if (sessionKeyCache != null)
        {
            mSessionKeyCache.putAll(sessionKeyCache);
        }

        mWrappedDecryptor = wrapped;
    }

    public boolean hasCachedSessionData(PGPPublicKeyEncryptedData encData) throws PGPException {
        ByteBuffer bi = ByteBuffer.wrap(encData.getSessionKey()[0]);
        return mSessionKeyCache.containsKey(bi);
    }

    public Map<ByteBuffer, byte[]> getCachedSessionKeys() {
        return Collections.unmodifiableMap(mSessionKeyCache);
    }

    public boolean canDecrypt() {
        return mWrappedDecryptor != null;
    }

    // BC 1.84's PublicKeyDataDecryptorFactory interface added a pkeskVersion parameter to
    // this method (and a new packet-based recoverSessionData(PublicKeyEncSessionPacket,
    // InputStreamPacket) overload, handled by AbstractPublicKeyDataDecryptorFactory - our new
    // superclass - in terms of this one, exactly as bc-java's own
    // JcePublicKeyDataDecryptorFactoryBuilder#build() does for the wrapped, non-caching case).
    // The old 2-arg overload this used to override is now provided by the superclass in terms
    // of this 3-arg one (defaulting pkeskVersion to VERSION_3), so no separate 2-arg override
    // is needed here.
    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion) throws PGPException {
        ByteBuffer bi = ByteBuffer.wrap(secKeyData[0]);  // encoded MPI
        if (mSessionKeyCache.containsKey(bi)) {
            return mSessionKeyCache.get(bi);
        }

        if (mWrappedDecryptor == null) {
            throw new IllegalStateException("tried to decrypt without wrapped decryptor, this is a bug!");
        }

        byte[] sessionData = mWrappedDecryptor.recoverSessionData(keyAlgorithm, secKeyData, pkeskVersion);
        mSessionKeyCache.put(bi, sessionData);
        return sessionData;
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
            throws PGPException {
        if (mWrappedDecryptor != null) {
            return mWrappedDecryptor.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }
        return mOperatorHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket,
            PGPSessionKey sessionKey) throws PGPException {
        if (mWrappedDecryptor != null) {
            mWrappedDecryptor.createDataDecryptor(aeadEncDataPacket, sessionKey);
        }
        return mAeadHelper.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd,
            PGPSessionKey sessionKey) throws PGPException {
        if (mWrappedDecryptor != null) {
            mWrappedDecryptor.createDataDecryptor(seipd, sessionKey);
        }
        return mAeadHelper.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }

}
