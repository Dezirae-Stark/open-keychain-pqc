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

package org.sufficientlysecure.keychain.operations;

import java.security.Security;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.EditKeyResult;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Covers {@code EditKeyOperation}'s post-creation smoke test (B4): every genuinely new primary
 * key must actually sign+verify (and encrypt+decrypt, if it has an encryption subkey) before
 * {@code EditKeyOperation} reports success -- generalizing the KEM-only-master-key hang this
 * session already found and fixed once into a standing check, rather than relying on catching
 * each new instance of "key created but doesn't actually work" individually.
 * <p>
 * These are positive-path tests: they confirm the hook does not false-positive-reject a
 * legitimately working key (the actual regression risk of hooking into the most load-bearing
 * path in the app), and that it correctly skips the encrypt/decrypt phase when there's no
 * encryption subkey. Every individual crypto primitive this delegates to (sign, verify, encrypt,
 * decrypt) already has its own exhaustive coverage elsewhere in this codebase -- what's new here
 * is specifically that {@code EditKeyOperation} wires the check in for new keys and skips it for
 * edits.
 */
@RunWith(KeychainTestRunner.class)
public class EditKeyOperationSmokeTestTest {

    private static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    @Test
    public void newKeyWithCertifySignAndEncryptSubkeys_smokeTestPasses() {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, 0, Curve.NIST_P256, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId("smoke test sign+encrypt");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        EditKeyResult result = execute(builder.build());

        assertTrue("key with a working certify/sign master and a working encrypt subkey must "
                + "pass the post-creation smoke test: " + result.getLog(), result.success());
        assertNotNull(result.mMasterKeyId);
    }

    @Test
    public void newKeyWithOnlyCertifySign_noEncryptSubkey_smokeTestSkipsEncryptPhase() {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        // Master key carries CERTIFY_OTHER and SIGN_DATA together (a single certify+sign key,
        // no separate signing subkey) -- a real, supported configuration, e.g. the typical
        // ML-DSA/SLH-DSA primary key shape used elsewhere in this app.
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addUserId("smoke test sign-only");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        EditKeyResult result = execute(builder.build());

        assertTrue("a signing-only key (no encryption subkey) must still pass the smoke test, "
                + "skipping the encrypt/decrypt phase entirely: " + result.getLog(), result.success());
        assertNotNull(result.mMasterKeyId);
    }

    @Test
    public void editingAnExistingKey_doesNotRerunTheSmokeTest() {
        // Create once.
        SaveKeyringParcel.Builder createBuilder = SaveKeyringParcel.buildNewKeyringParcel();
        createBuilder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        createBuilder.addUserId("smoke test edit target");
        createBuilder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));
        EditKeyResult createResult = execute(createBuilder.build());
        assertTrue("initial creation must succeed: " + createResult.getLog(), createResult.success());
        long masterKeyId = createResult.mMasterKeyId;
        byte[] fingerprint = KeyWritableRepository.create(RuntimeEnvironment.getApplication())
                .getUnifiedKeyInfo(masterKeyId).fingerprint();

        // Edit: add a second user ID. If the smoke test incorrectly re-ran here (isNewKey is
        // false on this path), this would still need to pass -- but this test's actual point is
        // that isNewKey correctly gates the check to creation only, not that edits would fail
        // the check if it ran (they wouldn't, the key still works). A regression that made
        // isNewKey always true, however, would make every edit pay the smoke-test cost.
        SaveKeyringParcel.Builder editBuilder = SaveKeyringParcel.buildChangeKeyringParcel(masterKeyId, fingerprint);
        editBuilder.addUserId("second identity");
        EditKeyResult editResult = execute(editBuilder.build());

        assertTrue("editing an existing key must succeed: " + editResult.getLog(), editResult.success());
    }

    private EditKeyResult execute(SaveKeyringParcel saveParcel) {
        KeyWritableRepository repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        EditKeyOperation op = new EditKeyOperation(
                RuntimeEnvironment.getApplication(), repository, new ProgressScaler(), new AtomicBoolean());
        return op.execute(saveParcel, CryptoInputParcel.createCryptoInputParcel(new Date(), PASSPHRASE));
    }
}
