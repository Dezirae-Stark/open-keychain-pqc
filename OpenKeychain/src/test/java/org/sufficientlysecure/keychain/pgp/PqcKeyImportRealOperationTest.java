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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.OpenPgpDecryptionResult;
import org.openintents.openpgp.OpenPgpSignatureResult;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.ImportOperation;
import org.sufficientlysecure.keychain.operations.results.DecryptVerifyResult;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.operations.results.PgpSignEncryptResult;
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlDsa65;
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlDsa87;
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlKem1024;
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlKem768;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.InputData;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Phase 5: verifies (and, where it found real gaps, fixes) that all 9 PQC algorithms (IDs 30,
 * 31, 32, 35, 36, 100, 101, 102, 103) survive a real export-then-reimport round trip through the
 * actual app entry point a caller uses -- {@link ImportOperation#execute}, which internally
 * calls {@link UncachedKeyRing#decodeFromData} and then {@code
 * KeyWritableRepository#saveSecretKeyRing}/{@code savePublicKeyRing} (both of which
 * canonicalize before persisting) -- rather than a bespoke test harness that bypasses any of
 * that machinery.
 * <p>
 * For each algorithm: generate a fresh keyring with {@link PgpKeyOperation} exactly as the
 * existing generation/"RealOperation" tests do, armor-encode it with {@link
 * UncachedKeyRing#encodeArmored}, wipe knowledge of the in-memory {@code UncachedKeyRing}
 * object and reimport the armored bytes through {@link ImportOperation#execute}, then confirm
 * the reimported key (fetched fresh from the {@link KeyWritableRepository} by master key ID) is
 * both structurally correct (fingerprint, per-key algorithm tags survive the round trip) and
 * functionally usable -- a real sign+verify or encrypt+decrypt performed with the
 * <em>reimported</em> key through {@link PgpSignEncryptOperation}/{@link
 * PgpDecryptVerifyOperation}, not the original in-memory key.
 * <p>
 * Two further tests ({@link #testImportForeignCompositeMlDsa87Ed448PublicKey} and {@link
 * #testImportForeignSlhDsaShake128sPublicKey}) go one step further for the two algorithms with
 * genuine foreign-generated test vectors on hand: they import the actual draft-ietf-openpgp-
 * pqc-17 published public-key fixtures ({@code test-keys/v6-mldsa-87-sample-pk.asc}, {@code
 * test-keys/v6-slhdsa-128s-sample-pk.asc}) through this same real {@link ImportOperation}
 * path, rather than the raw {@code PGPObjectFactory} the existing KAT tests use -- confirming
 * interop with an independently-generated key, not just a self-round-trip.
 */
@RunWith(KeychainTestRunner.class)
public class PqcKeyImportRealOperationTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    // -----------------------------------------------------------------------------------------
    // Composite signature algorithms (master-only keys)
    // -----------------------------------------------------------------------------------------

    @Test
    public void testImportCompositeMlDsa65Ed25519() throws Exception {
        UncachedKeyRing ring = generateMasterOnlySigningRing(
                Algorithm.ML_DSA_65_ED25519,
                "pqc-import-mldsa65 <pqc-import-30@example.org>",
                "composite ML-DSA-65+Ed25519 (algorithm 30)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertBasics(ring, PublicKeyAlgorithmTags.ML_DSA_65_Ed25519,
                "composite ML-DSA-65+Ed25519 (algorithm 30)");
        assertSignVerifyWorksWithReimportedKey(masterKeyId, "composite ML-DSA-65+Ed25519 (algorithm 30)");
    }

    @Test
    public void testImportCompositeMlDsa87Ed448() throws Exception {
        UncachedKeyRing ring = generateMasterOnlySigningRing(
                Algorithm.ML_DSA_87_ED448,
                "pqc-import-mldsa87 <pqc-import-31@example.org>",
                "composite ML-DSA-87+Ed448 (algorithm 31)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertBasics(ring, PublicKeyAlgorithmTags.ML_DSA_87_Ed448,
                "composite ML-DSA-87+Ed448 (algorithm 31)");
        assertSignVerifyWorksWithReimportedKey(masterKeyId, "composite ML-DSA-87+Ed448 (algorithm 31)");
    }

    @Test
    public void testImportSlhDsaShake128s() throws Exception {
        UncachedKeyRing ring = generateMasterOnlySigningRing(
                Algorithm.SLH_DSA_SHAKE_128S,
                "pqc-import-slhdsa <pqc-import-32@example.org>",
                "SLH-DSA-SHAKE-128s (algorithm 32)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertBasics(ring, PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S,
                "SLH-DSA-SHAKE-128s (algorithm 32)");
        assertSignVerifyWorksWithReimportedKey(masterKeyId, "SLH-DSA-SHAKE-128s (algorithm 32)");
    }

    @Test
    public void testImportStandaloneMlDsa65() throws Exception {
        UncachedKeyRing ring = generateMasterOnlySigningRing(
                Algorithm.STANDALONE_ML_DSA_65,
                "pqc-import-standalone-mldsa65 <pqc-import-102@example.org>",
                "standalone ML-DSA-65 (algorithm 102)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertBasics(ring, StandaloneMlDsa65.ALGORITHM_ID,
                "standalone ML-DSA-65 (algorithm 102)");
        assertSignVerifyWorksWithReimportedKey(masterKeyId, "standalone ML-DSA-65 (algorithm 102)");
    }

    @Test
    public void testImportStandaloneMlDsa87() throws Exception {
        UncachedKeyRing ring = generateMasterOnlySigningRing(
                Algorithm.STANDALONE_ML_DSA_87,
                "pqc-import-standalone-mldsa87 <pqc-import-103@example.org>",
                "standalone ML-DSA-87 (algorithm 103)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertBasics(ring, StandaloneMlDsa87.ALGORITHM_ID,
                "standalone ML-DSA-87 (algorithm 103)");
        assertSignVerifyWorksWithReimportedKey(masterKeyId, "standalone ML-DSA-87 (algorithm 103)");
    }

    // -----------------------------------------------------------------------------------------
    // KEM algorithms (certifying master key + a dedicated encryption subkey)
    // -----------------------------------------------------------------------------------------

    @Test
    public void testImportCompositeMlKem768X25519() throws Exception {
        SubkeyAdd master = SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, SaveKeyringParcel.Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L);
        UncachedKeyRing ring = generateMasterPlusKemSubkeyRing(master, Algorithm.ML_KEM_768_X25519,
                "pqc-import-mlkem768 <pqc-import-35@example.org>",
                "composite ML-KEM-768+X25519 (algorithm 35)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertSubkeyAlgorithm(ring, masterKeyId,
                PublicKeyAlgorithmTags.ML_KEM_768_X25519, "composite ML-KEM-768+X25519 (algorithm 35)");
        assertEncryptDecryptWorksWithReimportedKey(masterKeyId, "composite ML-KEM-768+X25519 (algorithm 35)");
    }

    @Test
    public void testImportCompositeMlKem1024X448() throws Exception {
        SubkeyAdd master = SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_DSA_87_ED448, null, null, KeyFlags.CERTIFY_OTHER, 0L);
        UncachedKeyRing ring = generateMasterPlusKemSubkeyRing(master, Algorithm.ML_KEM_1024_X448,
                "pqc-import-mlkem1024 <pqc-import-36@example.org>",
                "composite ML-KEM-1024+X448 (algorithm 36)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertSubkeyAlgorithm(ring, masterKeyId,
                PublicKeyAlgorithmTags.ML_KEM_1024_X448, "composite ML-KEM-1024+X448 (algorithm 36)");
        assertEncryptDecryptWorksWithReimportedKey(masterKeyId, "composite ML-KEM-1024+X448 (algorithm 36)");
    }

    @Test
    public void testImportStandaloneMlKem768() throws Exception {
        SubkeyAdd master = SubkeyAdd.createSubkeyAdd(
                Algorithm.SLH_DSA_SHAKE_128S, null, null, KeyFlags.CERTIFY_OTHER, 0L);
        UncachedKeyRing ring = generateMasterPlusKemSubkeyRing(master, Algorithm.STANDALONE_ML_KEM_768,
                "pqc-import-standalone-mlkem768 <pqc-import-100@example.org>",
                "standalone ML-KEM-768 (algorithm 100)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertSubkeyAlgorithm(ring, masterKeyId,
                StandaloneMlKem768.ALGORITHM_ID, "standalone ML-KEM-768 (algorithm 100)");
        assertEncryptDecryptWorksWithReimportedKey(masterKeyId, "standalone ML-KEM-768 (algorithm 100)");
    }

    @Test
    public void testImportStandaloneMlKem1024() throws Exception {
        SubkeyAdd master = SubkeyAdd.createSubkeyAdd(
                Algorithm.SLH_DSA_SHAKE_128S, null, null, KeyFlags.CERTIFY_OTHER, 0L);
        UncachedKeyRing ring = generateMasterPlusKemSubkeyRing(master, Algorithm.STANDALONE_ML_KEM_1024,
                "pqc-import-standalone-mlkem1024 <pqc-import-101@example.org>",
                "standalone ML-KEM-1024 (algorithm 101)");
        long masterKeyId = ring.getMasterKeyId();

        reimportSecretRingAndAssertSubkeyAlgorithm(ring, masterKeyId,
                StandaloneMlKem1024.ALGORITHM_ID, "standalone ML-KEM-1024 (algorithm 101)");
        assertEncryptDecryptWorksWithReimportedKey(masterKeyId, "standalone ML-KEM-1024 (algorithm 101)");
    }

    // -----------------------------------------------------------------------------------------
    // Foreign (independently-generated) test vectors, imported through the real path
    // -----------------------------------------------------------------------------------------

    /**
     * Imports draft-ietf-openpgp-pqc-17's own published composite ML-DSA-87+Ed448 public key
     * test vector through the real {@link ImportOperation#execute} path (not raw {@code
     * PGPObjectFactory}, which is what {@code CompositeMlDsa87Ed448SignVerifyTest}'s KAT test
     * uses) -- the strongest available check, since it succeeds only if the real {@code
     * decodeFromData}/{@code canonicalize}/{@code savePublicKeyRing} pipeline accepts a
     * genuinely foreign-generated key, not just a self-round-tripped one.
     */
    @Test
    public void testImportForeignCompositeMlDsa87Ed448PublicKey() throws Exception {
        byte[] pkBytes = readTestResource("/test-keys/v6-mldsa-87-sample-pk.asc");

        ImportOperation importOp = new ImportOperation(RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
        ImportKeyResult result = importOp.execute(
                ImportKeyringParcel.createFromBytes(pkBytes), CryptoInputParcel.createCryptoInputParcel());

        assertTrue("importing the official draft-ietf-openpgp-pqc-17 composite ML-DSA-87+Ed448 "
                + "public key through the real ImportOperation path must succeed: " + result.getLog(),
                result.success());
        assertEquals(1, result.mNewKeys);

        long importedMasterKeyId = result.getImportedMasterKeyIds()[0];
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        CanonicalizedPublicKeyRing reimported = repository.getCanonicalizedPublicKeyRing(importedMasterKeyId);
        assertNotNull("reimported public keyring must be retrievable from the repository", reimported);

        assertEquals("reimported foreign key's fingerprint must match the draft's published value",
                "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20",
                org.bouncycastle.util.encoders.Hex.toHexString(reimported.getFingerprint()));
        assertEquals("reimported foreign key must be recognized as algorithm 31",
                PublicKeyAlgorithmTags.ML_DSA_87_Ed448, reimported.getPublicKey(importedMasterKeyId).getAlgorithm());
    }

    /**
     * Same as {@link #testImportForeignCompositeMlDsa87Ed448PublicKey}, for the official
     * SLH-DSA-SHAKE-128s (algorithm 32) test vector.
     */
    @Test
    public void testImportForeignSlhDsaShake128sPublicKey() throws Exception {
        byte[] pkBytes = readTestResource("/test-keys/v6-slhdsa-128s-sample-pk.asc");

        ImportOperation importOp = new ImportOperation(RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
        ImportKeyResult result = importOp.execute(
                ImportKeyringParcel.createFromBytes(pkBytes), CryptoInputParcel.createCryptoInputParcel());

        assertTrue("importing the official draft-ietf-openpgp-pqc-17 SLH-DSA-SHAKE-128s public "
                + "key through the real ImportOperation path must succeed: " + result.getLog(),
                result.success());
        assertEquals(1, result.mNewKeys);

        long importedMasterKeyId = result.getImportedMasterKeyIds()[0];
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        CanonicalizedPublicKeyRing reimported = repository.getCanonicalizedPublicKeyRing(importedMasterKeyId);
        assertNotNull("reimported public keyring must be retrievable from the repository", reimported);

        assertEquals("reimported foreign key's fingerprint must match the draft's published value",
                "eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92",
                org.bouncycastle.util.encoders.Hex.toHexString(reimported.getFingerprint()));
        assertEquals("reimported foreign key must be recognized as algorithm 32",
                PublicKeyAlgorithmTags.SLH_DSA_SHAKE_128S, reimported.getPublicKey(importedMasterKeyId).getAlgorithm());
    }

    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    private static UncachedKeyRing generateMasterOnlySigningRing(Algorithm algorithm, String userId, String label)
            throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                algorithm, null, null, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId(userId);
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue(label + ": key generation must succeed: " + result.getLog(), result.success());
        assertNotNull(result.getRing());
        return result.getRing();
    }

    private static UncachedKeyRing generateMasterPlusKemSubkeyRing(
            SubkeyAdd master, Algorithm kemAlgorithm, String userId, String label) throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(master);
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                kemAlgorithm, null, null, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId(userId);
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue(label + ": key generation must succeed: " + result.getLog(), result.success());
        assertNotNull(result.getRing());
        return result.getRing();
    }

    /**
     * Armor-encodes {@code ring}'s secret key material and reimports the resulting bytes
     * through the real {@link ImportOperation#execute} path, then confirms the reimported
     * keyring is retrievable from the repository, has the original fingerprint, and its master
     * key carries {@code expectedMasterAlgorithm}.
     */
    private static void reimportSecretRingAndAssertBasics(
            UncachedKeyRing ring, int expectedMasterAlgorithm, String label) throws Exception {
        long masterKeyId = ring.getMasterKeyId();
        byte[] originalFingerprint = ring.getFingerprint();

        ImportKeyResult result = importArmoredSecretRing(ring);
        assertTrue(label + ": reimporting the exported secret keyring through the real "
                + "ImportOperation path must succeed: " + result.getLog(), result.success());
        assertEquals(label + ": exactly one new key must be reported", 1, result.mNewKeys);
        assertEquals(label + ": the reimported master key ID must match the original",
                masterKeyId, result.getImportedMasterKeyIds()[0]);

        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        CanonicalizedSecretKeyRing reimported = repository.getCanonicalizedSecretKeyRing(masterKeyId);
        assertNotNull(label + ": reimported secret keyring must be retrievable from the repository",
                reimported);
        assertArrayEquals(label + ": reimported key's fingerprint must match the original exactly",
                originalFingerprint, reimported.getFingerprint());
        assertEquals(label + ": reimported master key's algorithm tag must survive the round trip",
                expectedMasterAlgorithm, reimported.getPublicKey(masterKeyId).getAlgorithm());
    }

    /**
     * Same as {@link #reimportSecretRingAndAssertBasics}, but for a two-key (master + KEM
     * subkey) ring: additionally locates the non-master public key and asserts its algorithm.
     */
    private static void reimportSecretRingAndAssertSubkeyAlgorithm(
            UncachedKeyRing ring, long masterKeyId, int expectedSubkeyAlgorithm, String label) throws Exception {
        byte[] originalFingerprint = ring.getFingerprint();

        ImportKeyResult result = importArmoredSecretRing(ring);
        assertTrue(label + ": reimporting the exported secret keyring through the real "
                + "ImportOperation path must succeed: " + result.getLog(), result.success());
        assertEquals(label + ": exactly one new key must be reported", 1, result.mNewKeys);
        assertEquals(label + ": the reimported master key ID must match the original",
                masterKeyId, result.getImportedMasterKeyIds()[0]);

        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        CanonicalizedSecretKeyRing reimported = repository.getCanonicalizedSecretKeyRing(masterKeyId);
        assertNotNull(label + ": reimported secret keyring must be retrievable from the repository",
                reimported);
        assertArrayEquals(label + ": reimported key's fingerprint must match the original exactly",
                originalFingerprint, reimported.getFingerprint());

        CanonicalizedPublicKey subkey = null;
        for (CanonicalizedPublicKey key : reimported.publicKeyIterator()) {
            if (key.getKeyId() != masterKeyId) {
                subkey = key;
                break;
            }
        }
        assertNotNull(label + ": reimported keyring must still contain the KEM subkey", subkey);
        assertEquals(label + ": reimported KEM subkey's algorithm tag must survive the round trip",
                expectedSubkeyAlgorithm, subkey.getAlgorithm());
    }

    private static ImportKeyResult importArmoredSecretRing(UncachedKeyRing ring) throws Exception {
        ByteArrayOutputStream armored = new ByteArrayOutputStream();
        ring.encodeArmored(armored, null);

        ImportOperation importOp = new ImportOperation(RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
        return importOp.execute(
                ImportKeyringParcel.createFromBytes(armored.toByteArray()),
                CryptoInputParcel.createCryptoInputParcel());
    }

    private static void assertSignVerifyWorksWithReimportedKey(long masterKeyId, String label) throws Exception {
        String plaintext = "reimported " + label + " round trip works end-to-end ☭";
        byte[] signedMessage;

        { // sign via the real PgpSignEncryptOperation, using the reimported key from the repo
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes("UTF-8"));

            PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                    RuntimeEnvironment.getApplication(),
                    KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

            InputData data = new InputData(in, in.available());

            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
            pgpData.setSignatureMasterKeyId(masterKeyId);
            pgpData.setSignatureSubKeyId(masterKeyId);
            pgpData.setCleartextSignature(false);
            pgpData.setDetachedSignature(false);

            PgpSignEncryptResult result = op.execute(pgpData.build(),
                    CryptoInputParcel.createCryptoInputParcel(new Date(), PASSPHRASE), data, out);
            assertTrue(label + ": signing with the reimported key must succeed: " + result.getLog(),
                    result.success());

            signedMessage = out.toByteArray();
        }

        { // verify via the real PgpDecryptVerifyOperation
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(signedMessage);
            InputData data = new InputData(in, in.available());

            PgpDecryptVerifyOperation op = new PgpDecryptVerifyOperation(
                    RuntimeEnvironment.getApplication(),
                    KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
            PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder().build();
            DecryptVerifyResult result = op.execute(
                    input, CryptoInputParcel.createCryptoInputParcel(), data, out);

            assertTrue(label + ": verifying a signature made with the reimported key must "
                    + "succeed: " + result.getLog(), result.success());
            assertEquals(label + ": signatureResult should be RESULT_VALID_KEY_CONFIRMED",
                    OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED, result.getSignatureResult().getResult());
            assertArrayEquals(label + ": recovered plaintext must match the original exactly",
                    plaintext.getBytes("UTF-8"), out.toByteArray());
        }
    }

    private static void assertEncryptDecryptWorksWithReimportedKey(long masterKeyId, String label) throws Exception {
        String plaintext = "reimported " + label + " round trip works end-to-end ☭";
        byte[] ciphertext;

        { // encrypt via the real PgpSignEncryptOperation, targeting the reimported master key
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes("UTF-8"));

            PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                    RuntimeEnvironment.getApplication(),
                    KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

            InputData data = new InputData(in, in.available());

            PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
            pgpData.setEncryptionMasterKeyIds(new long[] { masterKeyId });
            pgpData.setSymmetricEncryptionAlgorithm(
                    PgpSecurityConstants.OpenKeychainSymmetricKeyAlgorithmTags.AES_256);

            PgpSignEncryptResult result = op.execute(pgpData.build(),
                    CryptoInputParcel.createCryptoInputParcel(new Date()), data, out);
            assertTrue(label + ": encrypting to the reimported key must succeed: " + result.getLog(),
                    result.success());

            ciphertext = out.toByteArray();
        }

        { // decrypt via the real PgpDecryptVerifyOperation, providing the passphrase directly
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
            InputData data = new InputData(in, in.available());

            PgpDecryptVerifyOperation op = new PgpDecryptVerifyOperation(
                    RuntimeEnvironment.getApplication(),
                    KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
            PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder().build();
            DecryptVerifyResult result = op.execute(
                    input, CryptoInputParcel.createCryptoInputParcel(PASSPHRASE), data, out);

            assertTrue(label + ": decrypting with the reimported key must succeed: " + result.getLog(),
                    result.success());
            assertArrayEquals(label + ": recovered plaintext must match the original exactly",
                    plaintext.getBytes("UTF-8"), out.toByteArray());
            assertEquals(label + ": decryptionResult should be RESULT_ENCRYPTED",
                    OpenPgpDecryptionResult.RESULT_ENCRYPTED, result.getDecryptionResult().getResult());
        }
    }

    private static byte[] readTestResource(String name) throws Exception {
        try (InputStream in = PqcKeyImportRealOperationTest.class.getResourceAsStream(name)) {
            assertNotNull("test resource must be present: " + name, in);
            return in.readAllBytes();
        }
    }
}
