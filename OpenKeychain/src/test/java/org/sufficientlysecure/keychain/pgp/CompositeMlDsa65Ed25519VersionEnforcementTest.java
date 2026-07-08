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
 * Confirms the "Confirmed gap" finding from the design doc's Phase 1 signing adversarial
 * review is actually closed: draft-ietf-openpgp-pqc-17 mandates composite
 * ML-DSA-65+Ed25519 (algorithm ID 30) be used "only with v6 keys ... v6 signatures ... full
 * stop", but nothing previously enforced that anywhere in {@link UncachedKeyRing}'s
 * canonicalization. This constructs a v4-framed algorithm-30 public key entirely in memory
 * (bypassing the wire parser's own version check, verified separately in the vendored BC
 * fork's {@code CompositeMlDsa65VersionEnforcementTest}) to isolate {@link
 * UncachedKeyRing#canonicalize}'s own defense-in-depth check, then confirms the same
 * malformed key is also rejected through the real, wire-level key-import path ({@link
 * UncachedKeyRing#decodeFromData}), which is what actually rejects it first in practice.
 */
@RunWith(KeychainTestRunner.class)
public class CompositeMlDsa65Ed25519VersionEnforcementTest {

    // Ed25519 (32) || ML-DSA-65 (1952), see PublicKeyPacket's private
    // COMPOSITE_ML_DSA_65_ED25519_PUBLIC_KEY_LEN.
    private static final int COMPOSITE_PUBLIC_KEY_LEN = 32 + 1952;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    /**
     * Isolates {@link UncachedKeyRing#canonicalize}'s own master-key version/algorithm check,
     * independent of the wire parser: a {@link PGPPublicKey} carrying a v4-versioned
     * {@link PublicKeyPacket} with algorithm 30 is built directly (this bypasses {@code
     * PublicKeyPacket.parseKey()} entirely -- exactly the "any PGPPublicKey constructed
     * in-memory without going through the wire parser" scenario the fix's defense-in-depth
     * comment calls out), then fed straight into canonicalize().
     */
    @Test
    public void v4FramedAlgorithm30MasterKeyRejectedByCanonicalize() throws Exception {
        PublicKeyPacket v4AlgorithmThirtyPacket = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.ML_DSA_65_Ed25519,
                new Date(),
                new OpaquePublicBCPGKey(new byte[COMPOSITE_PUBLIC_KEY_LEN]));
        assertEquals(PublicKeyPacket.VERSION_4, v4AlgorithmThirtyPacket.getVersion());

        PGPPublicKey maliciousMasterKey =
                new PGPPublicKey(v4AlgorithmThirtyPacket, new JcaKeyFingerprintCalculator());
        assertTrue("constructed key must present as a master key for this test to be valid",
                maliciousMasterKey.isMasterKey());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(maliciousMasterKey);
        PGPPublicKeyRing maliciousRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(maliciousRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("a v4-framed composite ML-DSA-65+Ed25519 master key must be rejected by "
                + "canonicalize(), not silently accepted: " + log, result);
        assertTrue("rejection should be logged with the version-mismatch error type: " + log,
                log.containsType(LogType.MSG_KC_ERROR_MASTER_ALGO_VERSION));
    }

    /**
     * Confirms the same malformed key is rejected through the real, wire-level key-import
     * path -- {@link UncachedKeyRing#decodeFromData}, which is what a caller importing a
     * foreign key actually calls. This exercises the packet-parser-level fix (in the
     * vendored BC fork's {@code PublicKeyPacket.parseKey()}): serializing the v4-framed
     * algorithm-30 packet built above to its raw wire bytes and re-parsing them from scratch
     * must fail during parsing itself, before canonicalize() is ever reached.
     */
    @Test
    public void v4FramedAlgorithm30KeyRejectedByRealImportPath() throws Exception {
        PublicKeyPacket v4AlgorithmThirtyPacket = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.ML_DSA_65_Ed25519,
                new Date(),
                new OpaquePublicBCPGKey(new byte[COMPOSITE_PUBLIC_KEY_LEN]));

        byte[] wireBytes = v4AlgorithmThirtyPacket.getEncoded();

        try {
            UncachedKeyRing.decodeFromData(wireBytes);
            fail("a v4-framed algorithm-30 (composite ML-DSA-65+Ed25519) public key must be "
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
     * Negative-space control for the two tests above: a legitimately v6-framed composite
     * ML-DSA-65+Ed25519 master key (same algorithm, same key length, only the version
     * differs) must still canonicalize successfully as far as this check is concerned --
     * confirming the fix rejects the version mismatch specifically, not algorithm 30 as a
     * whole. (Canonicalization still fails overall here for the unrelated, expected reason
     * that this synthetic key has no user ID -- the full legitimate round trip, including a
     * self-certified user ID, is already covered end-to-end by {@code
     * CompositeMlDsa65Ed25519RealOperationSignVerifyTest}.)
     */
    @Test
    public void v6FramedAlgorithm30MasterKeyNotRejectedForVersion() throws Exception {
        PublicKeyPacket v6AlgorithmThirtyPacket = new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.ML_DSA_65_Ed25519,
                new Date(),
                new OpaquePublicBCPGKey(new byte[COMPOSITE_PUBLIC_KEY_LEN]));

        PGPPublicKey legitimateMasterKey =
                new PGPPublicKey(v6AlgorithmThirtyPacket, new JcaKeyFingerprintCalculator());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(legitimateMasterKey);
        PGPPublicKeyRing legitimateRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(legitimateRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("this synthetic key has no user ID, so canonicalize() still fails overall "
                + "-- just not for the version-mismatch reason", result);
        Assert.assertFalse("a v6-framed composite ML-DSA-65+Ed25519 master key must not be "
                        + "flagged by the version-mismatch check: " + log,
                log.containsType(LogType.MSG_KC_ERROR_MASTER_ALGO_VERSION));
    }
}
