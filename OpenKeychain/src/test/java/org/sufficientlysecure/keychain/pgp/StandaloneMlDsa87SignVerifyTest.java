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

package org.sufficientlysecure.keychain.pgp;


import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.bcpg.OpaqueSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlDsa87;
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlDsa87ContentVerifierBuilderProvider;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Tests for standalone (non-composite, closed-ecosystem) ML-DSA-87 OpenPGP signing
 * (OpenKeychain private-use algorithm ID 103 -- NOT defined by draft-ietf-openpgp-pqc-17 or any
 * other spec; see docs/superpowers/specs/2026-07-07-pqc-migration-design.md, Standalone Mode
 * section): a real-keyring round trip through {@link PgpKeyOperation}/{@link
 * CanonicalizedSecretKey}/{@link CanonicalizedPublicKey} using the real {@link
 * PGPSignatureGenerator}/{@link PGPSignature} BC objects (validating the targeted bcpg-fork
 * patches), and negative controls (tampered signature, tampered digest, wrong key).
 * <p>
 * Unlike the composite ML-DSA classes, there is no official test vector for this private-use
 * algorithm to check a known-answer test against (no upstream implementation defines this code
 * point at all) -- so correctness here rests entirely on internal self-consistency (sign then
 * verify) plus the real BC packet-object-model round trip, mirroring {@code
 * StandaloneMlKem768EncryptDecryptTest}'s approach for the standalone encryption case. The real
 * end-to-end app-operation-level test ({@code StandaloneMlDsa87RealOperationSignVerifyTest})
 * exercises {@link PgpSignEncryptOperation}/{@link PgpDecryptVerifyOperation} directly; this
 * class focuses on the crypto core and its direct plumbing through the Canonicalized* classes
 * and BC's signature-packet object model.
 */
@RunWith(KeychainTestRunner.class)
public class StandaloneMlDsa87SignVerifyTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    static UncachedKeyRing sRing;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        // This codebase's own decision mandates v6-only keys/signatures for algorithm 103, and
        // requires the standalone key to certify its own user ID -- a certify+sign master key,
        // matching the shape every other v6-only signing algorithm in this codebase uses.
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.STANDALONE_ML_DSA_87, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("pqc-standalone-mldsa87-sign-test <pqc-standalone-sign87@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("standalone ML-DSA-87 key generation must succeed (this already exercises "
                + "v6 self-certification signing): " + result.getLog(), result.success());
        assertNotNull(result.getRing());

        sRing = result.getRing();
    }

    UncachedKeyRing ring;

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;
        ring = sRing;
    }

    /**
     * Canonicalization must not strip the standalone master key (the exact failure mode the
     * design doc calls out for {@code UncachedKeyRing.KNOWN_ALGORITHMS}), and it must be
     * recognized as signing-capable and secure via the private-use algorithm ID.
     */
    @Test
    public void testCanonicalizationKeepsStandaloneKey() {
        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = ring.canonicalize(log, 0);
        assertNotNull("canonicalization must succeed (see log: " + log + ")", canonicalized);

        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) canonicalized;
        CanonicalizedPublicKey masterKey = secretRing.getPublicKey(secretRing.getMasterKeyId());

        assertEquals(PublicKeyAlgorithmTags.EXPERIMENTAL_4, masterKey.getAlgorithm());
        assertTrue(masterKey.isStandaloneMlDsa87());
        assertTrue(masterKey.canSign());
        assertTrue(masterKey.canCertify());
        assertTrue("PgpSecurityConstants must not flag algorithm 103 as insecure/unidentified",
                masterKey.isSecure());
    }

    /**
     * Full round trip through the real BC signature-packet object model: build a v6 signature
     * using {@link CanonicalizedSecretKey#getDataSignatureGenerator} (which routes through
     * {@code StandaloneMlDsa87ContentSignerBuilder} and the bcpg-fork's patched {@code
     * PGPSignatureGenerator#generate()} native-encoding case), then verify it via a real {@link
     * PGPSignature#init}/{@link PGPSignature#verify} call (which routes through {@code
     * StandaloneMlDsa87ContentVerifierBuilderProvider} and the bcpg-fork's patched {@code
     * SignaturePacket} v6 parsing case).
     */
    @Test
    public void testSignatureRoundTripThroughRealPgpSignatureObject() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        assertNotNull(secretRing);
        long masterKeyId = secretRing.getMasterKeyId();

        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue("unlocking with the correct passphrase must succeed", secretKey.unlock(PASSPHRASE));

        byte[] message = "the OpenKeychain standalone ML-DSA-87 round trip works".getBytes("UTF-8");

        PGPSignatureGenerator sigGen = secretKey.getDataSignatureGenerator(
                PgpSecurityConstants.DEFAULT_HASH_ALGORITHM, false, null, null);
        sigGen.update(message);
        PGPSignature signature = sigGen.generate();

        assertEquals("signature packet must be tagged with the standalone algorithm ID",
                PublicKeyAlgorithmTags.EXPERIMENTAL_4, signature.getKeyAlgorithm());
        assertEquals("signature packet must be v6 (no v4 allowance for this algorithm)",
                6, signature.getVersion());
        assertEquals("raw signature value must be exactly the native ML-DSA-87 signature length",
                StandaloneMlDsa87.SIGNATURE_LEN, signature.getSignature().length);

        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(masterKeyId);

        PGPContentVerifierBuilderProvider verifierBuilderProvider =
                new StandaloneMlDsa87ContentVerifierBuilderProvider();
        signature.init(verifierBuilderProvider, publicKey.getPublicKey());
        signature.update(message);
        assertTrue("real PGPSignature.verify() must accept the genuine standalone signature",
                signature.verify());
    }

    /**
     * Tampered signature bytes must not verify, and a signature over a different digest must
     * not verify against this one either -- exercised directly against the standalone secret/
     * public key material.
     */
    @Test
    public void testTamperedSignatureIsRejected() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long masterKeyId = secretRing.getMasterKeyId();
        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue(secretKey.unlock(PASSPHRASE));
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(masterKeyId);

        byte[] secret = extractStandaloneSecretKeyBytes(secretKey);
        byte[] pub = publicKey.getOpaquePublicKeyMaterial();

        byte[] dataDigest = new byte[32];
        new SecureRandom().nextBytes(dataDigest);
        byte[] signature = StandaloneMlDsa87.sign(secret, dataDigest, new SecureRandom());
        assertTrue("sanity check: the untampered signature must verify",
                StandaloneMlDsa87.verify(pub, dataDigest, signature));

        byte[] tampered = signature.clone();
        tampered[100] ^= 0x01;
        assertFalse("a bit-flip in the ML-DSA-87 signature must be rejected",
                StandaloneMlDsa87.verify(pub, dataDigest, tampered));

        byte[] differentDigest = new byte[32];
        new SecureRandom().nextBytes(differentDigest);
        assertFalse("the signature must not verify over a different dataDigest",
                StandaloneMlDsa87.verify(pub, differentDigest, signature));
    }

    /** Verifying with an unrelated key's public material must not succeed. */
    @Test
    public void testWrongKeyCannotVerify() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long masterKeyId = secretRing.getMasterKeyId();
        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue(secretKey.unlock(PASSPHRASE));

        byte[] secret = extractStandaloneSecretKeyBytes(secretKey);

        byte[] dataDigest = new byte[32];
        new SecureRandom().nextBytes(dataDigest);
        byte[] signature = StandaloneMlDsa87.sign(secret, dataDigest, new SecureRandom());

        StandaloneMlDsa87.KeyMaterial unrelatedKey = StandaloneMlDsa87.generateKeyPair(new SecureRandom());

        assertFalse("verifying with an unrelated key's public material must not succeed",
                StandaloneMlDsa87.verify(unrelatedKey.publicKeyBytes, dataDigest, signature));
    }

    /**
     * Negative control on the digest-size floor itself: a signature made against a digest
     * shorter than the 256-bit hygiene floor must be rejected by {@link
     * StandaloneMlDsa87#verify}, confirming the floor is actually enforced and not merely
     * documented.
     */
    @Test
    public void testShortDigestIsRejectedByVerify() throws Exception {
        OperationLog log = new OperationLog();
        CanonicalizedSecretKeyRing secretRing = (CanonicalizedSecretKeyRing) ring.canonicalize(log, 0);
        long masterKeyId = secretRing.getMasterKeyId();
        CanonicalizedSecretKey secretKey = secretRing.getSecretKey(masterKeyId);
        assertTrue(secretKey.unlock(PASSPHRASE));
        CanonicalizedPublicKey publicKey = secretRing.getPublicKey(masterKeyId);
        byte[] pub = publicKey.getOpaquePublicKeyMaterial();

        byte[] secret = extractStandaloneSecretKeyBytes(secretKey);
        byte[] adequateDigest = new byte[32];
        new SecureRandom().nextBytes(adequateDigest);
        byte[] signature = StandaloneMlDsa87.sign(secret, adequateDigest, new SecureRandom());

        byte[] shortDigest = new byte[20]; // 160 bits, e.g. SHA-1-sized -- below the floor
        new SecureRandom().nextBytes(shortDigest);
        assertFalse("verify() must reject a sub-256-bit dataDigest outright",
                StandaloneMlDsa87.verify(pub, shortDigest, signature));
    }

    private static byte[] extractStandaloneSecretKeyBytes(CanonicalizedSecretKey secretKey) {
        Object secretKeyDataPacket = secretKey.getPrivateKey().getPrivateKeyDataPacket();
        byte[] rawSecretKeyData = ((OpaqueSecretBCPGKey) secretKeyDataPacket).getEncoded();
        return Arrays.copyOf(rawSecretKeyData, StandaloneMlDsa87.SECRET_KEY_LEN);
    }
}
