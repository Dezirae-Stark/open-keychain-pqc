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
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.OpaquePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.pgp.pqc.StandaloneMlDsa65;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Confirms {@link UncachedKeyRing#canonicalize} and the real wire-level import path both
 * enforce the v6-only requirement for standalone (non-composite, closed-ecosystem) ML-DSA-65
 * (OpenKeychain private-use algorithm ID 102 -- NOT defined by draft-ietf-openpgp-pqc-17 or any
 * other spec; this codebase's own decision, see
 * docs/superpowers/specs/2026-07-07-pqc-migration-design.md, Standalone Mode section, §3).
 * Mirrors {@code StandaloneMlKem768VersionEnforcementTest} exactly (same v6-only shape),
 * confirming the same three-layer defense-in-depth pattern applies identically to a standalone
 * signing algorithm as to a standalone KEM.
 */
@RunWith(KeychainTestRunner.class)
public class StandaloneMlDsa65VersionEnforcementTest {

    private static final int STANDALONE_PUBLIC_KEY_LEN = 1952; // raw ML-DSA-65 public key

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    /**
     * Isolates {@link UncachedKeyRing#canonicalize}'s own master-key version/algorithm check,
     * independent of the wire parser: a {@link PGPPublicKey} carrying a v4-versioned
     * {@link PublicKeyPacket} with algorithm 102 is built directly (bypassing {@code
     * PublicKeyPacket.parseKey()} entirely), then fed straight into canonicalize().
     */
    @Test
    public void v4FramedAlgorithm102MasterKeyRejectedByCanonicalize() throws Exception {
        PublicKeyPacket v4AlgorithmOneHundredTwo = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.EXPERIMENTAL_3,
                new Date(),
                new OpaquePublicBCPGKey(new byte[STANDALONE_PUBLIC_KEY_LEN]));
        assertEquals(PublicKeyPacket.VERSION_4, v4AlgorithmOneHundredTwo.getVersion());

        PGPPublicKey maliciousMasterKey =
                new PGPPublicKey(v4AlgorithmOneHundredTwo, new JcaKeyFingerprintCalculator());
        assertTrue("constructed key must present as a master key for this test to be valid",
                maliciousMasterKey.isMasterKey());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(maliciousMasterKey);
        PGPPublicKeyRing maliciousRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(maliciousRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("a v4-framed standalone ML-DSA-65 master key must be rejected by "
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
    public void v4FramedAlgorithm102KeyRejectedByRealImportPath() throws Exception {
        PublicKeyPacket v4AlgorithmOneHundredTwo = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.EXPERIMENTAL_3,
                new Date(),
                new OpaquePublicBCPGKey(new byte[STANDALONE_PUBLIC_KEY_LEN]));

        byte[] wireBytes = v4AlgorithmOneHundredTwo.getEncoded();

        try {
            UncachedKeyRing.decodeFromData(wireBytes);
            fail("a v4-framed algorithm-102 (standalone ML-DSA-65) public key must be "
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
     * Negative-space control: a legitimately v6-framed standalone ML-DSA-65 master key (same
     * algorithm, same key length, only the version differs) must still canonicalize
     * successfully as far as this check is concerned -- confirming the fix rejects the version
     * mismatch specifically, not algorithm 102 as a whole.
     */
    @Test
    public void v6FramedAlgorithm102MasterKeyNotRejectedForVersion() throws Exception {
        PublicKeyPacket v6AlgorithmOneHundredTwo = new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.EXPERIMENTAL_3,
                new Date(),
                new OpaquePublicBCPGKey(new byte[STANDALONE_PUBLIC_KEY_LEN]));

        PGPPublicKey legitimateMasterKey =
                new PGPPublicKey(v6AlgorithmOneHundredTwo, new JcaKeyFingerprintCalculator());

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(legitimateMasterKey);
        PGPPublicKeyRing legitimateRing = new PGPPublicKeyRing(keys);

        UncachedKeyRing uncachedRing = new UncachedKeyRing(legitimateRing);

        OperationLog log = new OperationLog();
        CanonicalizedKeyRing result = uncachedRing.canonicalize(log, 0);

        assertNull("this synthetic key has no user ID, so canonicalize() still fails overall "
                + "-- just not for the version-mismatch reason", result);
        Assert.assertFalse("a v6-framed standalone ML-DSA-65 master key must not be "
                        + "flagged by the version-mismatch check: " + log,
                log.containsType(LogType.MSG_KC_ERROR_MASTER_ALGO_VERSION));
    }

    /**
     * Confirms the standalone {@code SignaturePacket} parser-level v6-only enforcement too
     * (§4 of the design decisions -- the first defense-in-depth layer, signature-packet half):
     * a v4-framed signature packet claiming algorithm 102 must be rejected during parsing
     * itself, exercising the bcpg fork's {@code SignaturePacket.parseSignature()} explicit
     * {@code EXPERIMENTAL_3} case rather than the generic {@code EXPERIMENTAL_1..
     * EXPERIMENTAL_11} fallback (which has no version check or fixed-length check at all).
     */
    @Test
    public void v4FramedAlgorithm102SignaturePacketRejectedByParser() throws Exception {
        SignaturePacket v4Sig = new SignaturePacket(
                SignaturePacket.VERSION_4,
                PGPSignature.BINARY_DOCUMENT,
                0L,
                PublicKeyAlgorithmTags.EXPERIMENTAL_3,
                HashAlgorithmTags.SHA256,
                new SignatureSubpacket[0],
                new SignatureSubpacket[0],
                new byte[2],
                new byte[StandaloneMlDsa65.SIGNATURE_LEN],
                null);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(bos);
        v4Sig.encode(bcpgOut);
        bcpgOut.close();

        BCPGInputStream bcpgIn = new BCPGInputStream(new ByteArrayInputStream(bos.toByteArray()));
        try {
            bcpgIn.readPacket();
            fail("a v4-framed algorithm-102 (standalone ML-DSA-65) signature packet must be "
                    + "rejected by the real packet parser, not parsed and accepted");
        } catch (IOException expected) {
            assertTrue("rejection reason should mention the version mismatch: "
                            + expected.getMessage(),
                    expected.getMessage() != null && expected.getMessage().contains("version 6"));
        }
    }
}
