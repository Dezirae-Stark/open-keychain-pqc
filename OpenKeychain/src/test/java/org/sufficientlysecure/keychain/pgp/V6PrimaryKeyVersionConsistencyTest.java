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


import java.security.Security;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.ProgressScaler;
import org.sufficientlysecure.keychain.util.TestingUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Covers the actual gap identified for Phase 6b: reachability of a v6-only PQC master key was
 * already wired up (via {@code EditKeyFragment}/{@code SubkeysAddedAdapter}/{@code
 * AddSubkeyDialogFragment}, see that phase's research), and master-key generation already
 * respected algorithm-driven versioning (master and subkey generation share {@link
 * PgpKeyOperation#createKey}). The real, previously-unguarded gap was version *consistency*
 * between a v6-only PQC master key and any classical (RSA/DSA/ElGamal/ECDSA/ECDH/EdDSA)
 * subkeys queued alongside it -- e.g. the default ECDH encryption subkey Constants'
 * addDefaultSubkeys() queues, left untouched when only the master-key entry is swapped to a
 * PQC algorithm via the existing "tap position 0" UI flow.
 * <p>
 * This class tests the fix directly at the {@link PgpKeyOperation}/{@link UncachedKeyRing}
 * level: a classical subkey added alongside a v6 PQC master is now generated at the master's
 * own version (v6), not unconditionally at v4 as before, and {@link UncachedKeyRing#canonicalize}
 * carries a general backstop that rejects any classical subkey whose version doesn't match its
 * primary key's, independent of how the mismatch might have arisen.
 */
@RunWith(KeychainTestRunner.class)
public class V6PrimaryKeyVersionConsistencyTest {

    static final Passphrase PASSPHRASE = TestingUtils.testPassphrase0;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    /**
     * The exact end-to-end scenario the task calls for: a v6-only PQC signing algorithm
     * (composite ML-DSA-65+Ed25519) as the primary/master key, plus a classical ECDH
     * encryption subkey queued alongside it -- exactly what's left in the queue if a user
     * swaps only the master-key entry (position 0) via the existing "change master key" UI
     * flow and leaves the default ECDH subkey (position 1) untouched. Before the fix, this
     * would have produced a v6 master with a v4 ECDH subkey underneath it (mismatched,
     * unguarded); the fix threads the master's actual version through to classical-algorithm
     * subkey generation, so the ECDH subkey now comes out v6 too, matching the master.
     */
    @Test
    public void classicalSubkeyQueuedAlongsideV6PqcMaster_isAutoUpgradedToMatchMasterVersion()
            throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_DSA_65_ED25519, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        // the exact default ECDH encryption subkey Constants#addDefaultSubkeys queues,
        // left over from the pre-Phase-6b default configuration
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, null, Curve.CV25519,
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, 0L));
        builder.addUserId("v6-master-classical-subkey-test <v6-master@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("v6 master + classical subkey creation must succeed: " + result.getLog(),
                result.success());
        assertNotNull(result.getRing());

        UncachedKeyRing ring = result.getRing();
        Iterator<PGPPublicKey> keys = ring.mRing.getPublicKeys();
        PGPPublicKey master = keys.next();
        PGPPublicKey subkey = keys.next();
        assertFalse("there should be exactly two keys in this ring", keys.hasNext());

        assertTrue("first key must present as the master key", master.isMasterKey());
        assertFalse("second key must present as a subkey", subkey.isMasterKey());

        assertEquals("composite ML-DSA-65+Ed25519 master must be v6, as mandated by the draft",
                PublicKeyPacket.VERSION_6, master.getVersion());
        assertEquals("the classical ECDH subkey must be auto-upgraded to match the v6 master's "
                        + "version, not silently left at v4",
                PublicKeyPacket.VERSION_6, subkey.getVersion());

        // and the resulting keyring must canonicalize cleanly -- no version-mismatch flag
        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = ring.canonicalize(log, 0);
        assertNotNull("a version-consistent v6 keyring must canonicalize successfully: " + log,
                canonicalized);
        assertFalse("no version-mismatch should be flagged for a consistent v6 keyring: " + log,
                log.containsType(LogType.MSG_KC_SUB_VERSION_MISMATCH));
    }

    /**
     * Sanity check that the historical default (classical EDDSA master + classical ECDH
     * subkey, both v4) is completely unaffected by the version-threading fix: with no v6-only
     * PQC algorithm anywhere in the parcel, both keys must still come out v4, exactly as
     * before.
     */
    @Test
    public void classicalMasterAndSubkey_stayV4AsBefore() throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.EDDSA, null, Curve.CV25519,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, null, Curve.CV25519,
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, 0L));
        builder.addUserId("classical-default-test <classical-default@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("classical key creation must still succeed: " + result.getLog(),
                result.success());

        UncachedKeyRing ring = result.getRing();
        Iterator<PGPPublicKey> keys = ring.mRing.getPublicKeys();
        PGPPublicKey master = keys.next();
        PGPPublicKey subkey = keys.next();

        assertEquals("classical EdDSA master must stay v4, unchanged from before this fix",
                PublicKeyPacket.VERSION_4, master.getVersion());
        assertEquals("classical ECDH subkey must stay v4 under a v4 master, unchanged from "
                        + "before this fix",
                PublicKeyPacket.VERSION_4, subkey.getVersion());
    }

    /**
     * The full recommended real-UI end-to-end path from the research findings: master = a
     * v6-only PQC signing algorithm (standalone ML-DSA-65, this codebase's own closed-ecosystem
     * algorithm), subkey = a compatible composite ML-KEM-768+X25519 encryption key -- exactly
     * the shape a user reaches by tapping the master-key row, choosing a PQC signing algorithm,
     * removing the leftover default ECDH subkey, and adding a v6-compatible KEM subkey via the
     * existing "Add subkey" action, all through code paths already wired up before this task.
     */
    @Test
    public void v6PqcMasterWithCompositeKemSubkey_createdTogetherSuccessfully() throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.STANDALONE_ML_DSA_65, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_KEM_768_X25519, null, null, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId("pure-pqc-keyring-test <pure-pqc@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue("standalone ML-DSA-65 master + composite ML-KEM-768+X25519 subkey creation "
                + "must succeed together: " + result.getLog(), result.success());
        assertNotNull(result.getRing());

        UncachedKeyRing ring = result.getRing();
        Iterator<PGPPublicKey> keys = ring.mRing.getPublicKeys();
        PGPPublicKey master = keys.next();
        PGPPublicKey subkey = keys.next();

        assertEquals(PublicKeyPacket.VERSION_6, master.getVersion());
        assertEquals(PublicKeyPacket.VERSION_4, subkey.getVersion()); // algorithm 35's explicit v4 allowance

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = ring.canonicalize(log, 0);
        assertNotNull("a legitimately mixed-version (v6 master + v4-allowed algorithm-35 "
                + "subkey) keyring must still canonicalize successfully: " + log, canonicalized);
    }

    /**
     * Isolates {@link UncachedKeyRing#canonicalize}'s new general master-vs-subkey
     * version-consistency backstop, independent of whether {@link PgpKeyOperation} could ever
     * produce this shape itself post-fix: a classical ECDH subkey whose packet version was
     * forced back down to v4 underneath a v6 master must be rejected, not silently accepted.
     * This is the defense-in-depth check for any keyring reaching canonicalize() by some other
     * route (import, hand-built data) than the generation path fixed above.
     */
    @Test
    public void handCraftedV4ClassicalSubkeyUnderV6Master_rejectedByCanonicalize() throws Exception {
        // Build a real, legitimately consistent v6-master + v6-ECDH-subkey ring first, via the
        // real (fixed) creation path, so the subkey binding signature is a real, meaningful
        // signature object -- not a fabricated one -- exactly the same technique used by
        // CompositeMlDsa65Ed25519VersionEnforcementTest for the master-key-only case.
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_DSA_65_ED25519, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, null, Curve.CV25519,
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, 0L));
        builder.addUserId("hand-crafted-mismatch-test <hand-crafted@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue(result.success());

        UncachedKeyRing ring = result.getRing();
        Iterator<PGPPublicKey> keys = ring.mRing.getPublicKeys();
        PGPPublicKey master = keys.next();
        PGPPublicKey legitimateV6Subkey = keys.next();
        assertEquals(PublicKeyPacket.VERSION_6, legitimateV6Subkey.getVersion());

        // now tamper: rebuild the same subkey's packet at v4 instead of v6, preserving its
        // algorithm/creation-time/key material and re-attaching the *same* (now
        // fingerprint-inconsistent, but structurally present) binding signature -- the
        // version-consistency check runs before signature validation in canonicalize()'s
        // subkey loop, so this is sufficient to isolate that specific check.
        PGPSignature bindingSig = legitimateV6Subkey.getSignatures().next();
        PublicKeyPacket downgradedPacket = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                legitimateV6Subkey.getAlgorithm(),
                legitimateV6Subkey.getCreationTime(),
                legitimateV6Subkey.getPublicKeyPacket().getKey());
        PGPPublicKey masterShapedKey =
                new PGPPublicKey(downgradedPacket, new JcaKeyFingerprintCalculator());
        PGPPublicKey tamperedSubkey =
                PGPPublicKey.addSubkeyBindingCertification(masterShapedKey, bindingSig);
        assertEquals(PublicKeyPacket.VERSION_4, tamperedSubkey.getVersion());

        List<PGPPublicKey> tamperedKeys = new ArrayList<>();
        tamperedKeys.add(master);
        tamperedKeys.add(tamperedSubkey);
        PGPPublicKeyRing tamperedRing = new PGPPublicKeyRing(tamperedKeys);
        UncachedKeyRing uncachedTamperedRing = new UncachedKeyRing(tamperedRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalizedTampered = uncachedTamperedRing.canonicalize(log, 0);

        assertTrue("the version-mismatch check must flag and remove the tampered v4 subkey "
                + "under the v6 master: " + log,
                log.containsType(LogType.MSG_KC_SUB_VERSION_MISMATCH));

        if (canonicalizedTampered != null) {
            Iterator<org.sufficientlysecure.keychain.pgp.UncachedPublicKey> remaining =
                    canonicalizedTampered.getUncachedKeyRing().getPublicKeys();
            int count = 0;
            while (remaining.hasNext()) {
                remaining.next();
                count++;
            }
            assertEquals("the mismatched subkey must have been dropped, leaving only the master",
                    1, count);
        }
    }

    /**
     * Negative-space control: a v6-framed ECDH subkey under a v6 master (the fixed,
     * correct output) must not be flagged by the same check.
     */
    @Test
    public void consistentV6ClassicalSubkey_notFlaggedByVersionMismatchCheck() throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ML_DSA_65_ED25519, null, null,
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, null, Curve.CV25519,
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, 0L));
        builder.addUserId("consistent-v6-test <consistent-v6@example.org>");
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler());
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        assertTrue(result.success());

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing canonicalized = result.getRing().canonicalize(log, 0);
        assertNotNull(canonicalized);
        assertFalse(log.containsType(LogType.MSG_KC_SUB_VERSION_MISMATCH));
    }
}
