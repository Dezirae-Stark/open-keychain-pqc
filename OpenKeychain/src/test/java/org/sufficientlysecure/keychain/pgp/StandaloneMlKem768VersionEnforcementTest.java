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
 * enforce the v6-only requirement for standalone (non-composite, closed-ecosystem) ML-KEM-768
 * (OpenKeychain private-use algorithm ID 100 -- NOT defined by draft-ietf-openpgp-pqc-17 or any
 * other spec; this codebase's own decision, see
 * docs/superpowers/specs/2026-07-07-pqc-migration-design.md, Standalone Mode section, §3).
 * Mirrors {@code CompositeMlKem1024X448VersionEnforcementTest} exactly (same v6-only shape),
 * confirming the same three-layer defense-in-depth pattern applies identically to a
 * private-use algorithm ID as to an IANA-registered one.
 */
@RunWith(KeychainTestRunner.class)
public class StandaloneMlKem768VersionEnforcementTest {

    private static final int STANDALONE_PUBLIC_KEY_LEN = 1184; // raw ML-KEM-768 public key

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    /**
     * Isolates {@link UncachedKeyRing#canonicalize}'s own master-key version/algorithm check,
     * independent of the wire parser: a {@link PGPPublicKey} carrying a v4-versioned
     * {@link PublicKeyPacket} with algorithm 100 is built directly (bypassing {@code
     * PublicKeyPacket.parseKey()} entirely), then fed straight into canonicalize().
     */
    @Test
    public void v4FramedAlgorithm100MasterKeyRejectedByCanonicalize() throws Exception {
        PublicKeyPacket v4AlgorithmOneHundred = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.EXPERIMENTAL_1,
                new Date(),
                new OpaquePublicBCPGKey(new byte[STANDALONE_PUBLIC_KEY_LEN]));
        assertEquals(PublicKeyPacket.VERSION_4, v4AlgorithmOneHundred.getVersion());

        PGPPublicKey maliciousMasterKey =
                new PGPPublicKey(v4AlgorithmOneHundred, new JcaKeyFingerprintCalculator());
        assertTrue("constructed key must present as a master key for this test to be valid",
                maliciousMasterKey.isMasterKey());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(maliciousMasterKey);
        PGPPublicKeyRing maliciousRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(maliciousRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("a v4-framed standalone ML-KEM-768 master key must be rejected by "
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
    public void v4FramedAlgorithm100KeyRejectedByRealImportPath() throws Exception {
        PublicKeyPacket v4AlgorithmOneHundred = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.EXPERIMENTAL_1,
                new Date(),
                new OpaquePublicBCPGKey(new byte[STANDALONE_PUBLIC_KEY_LEN]));

        byte[] wireBytes = v4AlgorithmOneHundred.getEncoded();

        try {
            UncachedKeyRing.decodeFromData(wireBytes);
            fail("a v4-framed algorithm-100 (standalone ML-KEM-768) public key must be "
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
     * Negative-space control: a legitimately v6-framed standalone ML-KEM-768 master key (same
     * algorithm, same key length, only the version differs) must still canonicalize
     * successfully as far as this check is concerned -- confirming the fix rejects the version
     * mismatch specifically, not algorithm 100 as a whole.
     */
    @Test
    public void v6FramedAlgorithm100MasterKeyNotRejectedForVersion() throws Exception {
        PublicKeyPacket v6AlgorithmOneHundred = new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.EXPERIMENTAL_1,
                new Date(),
                new OpaquePublicBCPGKey(new byte[STANDALONE_PUBLIC_KEY_LEN]));

        PGPPublicKey legitimateMasterKey =
                new PGPPublicKey(v6AlgorithmOneHundred, new JcaKeyFingerprintCalculator());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(legitimateMasterKey);
        PGPPublicKeyRing legitimateRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(legitimateRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("this synthetic key has no user ID, so canonicalize() still fails overall "
                + "-- just not for the version-mismatch reason", result);
        Assert.assertFalse("a v6-framed standalone ML-KEM-768 master key must not be "
                        + "flagged by the version-mismatch check: " + log,
                log.containsType(LogType.MSG_KC_ERROR_MASTER_ALGO_VERSION));
    }
}
