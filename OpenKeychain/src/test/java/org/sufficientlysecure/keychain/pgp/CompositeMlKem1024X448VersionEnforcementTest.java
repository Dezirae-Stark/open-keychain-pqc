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
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.OpaquePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Confirms {@link UncachedKeyRing#canonicalize} and the real wire-level import path both
 * enforce the v6-only requirement for composite ML-KEM-1024+X448 (algorithm ID 36):
 * draft-ietf-openpgp-pqc-17 states this algorithm "MUST be used only with v6 keys" -- in
 * direct textual contrast to the immediately preceding sentence granting its sibling
 * composite KEM, ML-KEM-768+X25519 (algorithm 35), a v4-encryption-subkey carve-out. Mirrors
 * {@code CompositeMlDsa87Ed448VersionEnforcementTest} exactly (same v6-only shape), but for
 * an encryption-KEM algorithm rather than a signature algorithm, and -- critically -- as the
 * negative-space control proving algorithm 36 does *not* inherit algorithm 35's v4 allowance.
 */
@RunWith(KeychainTestRunner.class)
public class CompositeMlKem1024X448VersionEnforcementTest {

    // X448 (56) || ML-KEM-1024 (1568), see PublicKeyPacket's private
    // COMPOSITE_ML_KEM_1024_X448_PUBLIC_KEY_LEN.
    private static final int COMPOSITE_PUBLIC_KEY_LEN = 56 + 1568;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    /**
     * Isolates {@link UncachedKeyRing#canonicalize}'s own master-key version/algorithm check,
     * independent of the wire parser: a {@link PGPPublicKey} carrying a v4-versioned
     * {@link PublicKeyPacket} with algorithm 36 is built directly (bypassing {@code
     * PublicKeyPacket.parseKey()} entirely), then fed straight into canonicalize().
     * <p>
     * This is the negative-space control for algorithm 35's own v4 allowance: if this test
     * failed (i.e. a v4-framed algorithm-36 key were silently accepted), the most likely bug
     * would be treating algorithm 36 as inheriting algorithm 35's v4-allowed exception --
     * which the fetched spec text explicitly rules out.
     */
    @Test
    public void v4FramedAlgorithm36MasterKeyRejectedByCanonicalize() throws Exception {
        PublicKeyPacket v4AlgorithmThirtySix = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.ML_KEM_1024_X448,
                new Date(),
                new OpaquePublicBCPGKey(new byte[COMPOSITE_PUBLIC_KEY_LEN]));
        assertEquals(PublicKeyPacket.VERSION_4, v4AlgorithmThirtySix.getVersion());

        PGPPublicKey maliciousMasterKey =
                new PGPPublicKey(v4AlgorithmThirtySix, new JcaKeyFingerprintCalculator());
        assertTrue("constructed key must present as a master key for this test to be valid",
                maliciousMasterKey.isMasterKey());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(maliciousMasterKey);
        PGPPublicKeyRing maliciousRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(maliciousRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("a v4-framed composite ML-KEM-1024+X448 master key must be rejected by "
                + "canonicalize(), not silently accepted: " + log, result);
        assertTrue("rejection should be logged with the version-mismatch error type: " + log,
                log.containsType(LogType.MSG_KC_ERROR_MASTER_ALGO_VERSION));
    }

    /**
     * Confirms the same malformed key is rejected through the real, wire-level key-import
     * path -- {@link UncachedKeyRing#decodeFromData} -- exercising the packet-parser-level fix
     * in the vendored BC fork's {@code PublicKeyPacket.parseKey()}.
     */
    @Test
    public void v4FramedAlgorithm36KeyRejectedByRealImportPath() throws Exception {
        PublicKeyPacket v4AlgorithmThirtySix = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.ML_KEM_1024_X448,
                new Date(),
                new OpaquePublicBCPGKey(new byte[COMPOSITE_PUBLIC_KEY_LEN]));

        byte[] wireBytes = v4AlgorithmThirtySix.getEncoded();

        try {
            UncachedKeyRing.decodeFromData(wireBytes);
            fail("a v4-framed algorithm-36 (composite ML-KEM-1024+X448) public key must be "
                    + "rejected by the real key-import path, not parsed and accepted");
        } catch (java.io.IOException expected) {
            // Thrown by the vendored BC fork's PublicKeyPacket.parseKey() version check --
            // the packet never even makes it far enough to become an UncachedKeyRing.
            assertTrue("rejection reason should mention the version mismatch: "
                            + expected.getMessage(),
                    expected.getMessage() != null && expected.getMessage().contains("version 6"));
        }
    }

    /**
     * Negative-space control: a legitimately v6-framed composite ML-KEM-1024+X448 master key
     * (same algorithm, same key length, only the version differs) must still canonicalize
     * successfully as far as this check is concerned -- confirming the fix rejects the
     * version mismatch specifically, not algorithm 36 as a whole.
     */
    @Test
    public void v6FramedAlgorithm36MasterKeyNotRejectedForVersion() throws Exception {
        PublicKeyPacket v6AlgorithmThirtySix = new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.ML_KEM_1024_X448,
                new Date(),
                new OpaquePublicBCPGKey(new byte[COMPOSITE_PUBLIC_KEY_LEN]));

        PGPPublicKey legitimateMasterKey =
                new PGPPublicKey(v6AlgorithmThirtySix, new JcaKeyFingerprintCalculator());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(legitimateMasterKey);
        PGPPublicKeyRing legitimateRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(legitimateRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("this synthetic key has no user ID, so canonicalize() still fails overall "
                + "-- just not for the version-mismatch reason", result);
        Assert.assertFalse("a v6-framed composite ML-KEM-1024+X448 master key must not be "
                        + "flagged by the version-mismatch check: " + log,
                log.containsType(LogType.MSG_KC_ERROR_MASTER_ALGO_VERSION));
    }
}
