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

package org.sufficientlysecure.keychain.socialrecovery;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Mandatory adversarial coverage for B7's split/reconstruct core, per the plan's Tier-1 test
 * list, adjusted where the empirical spike (recorded in {@link WeightedShareSplitter}'s class
 * doc) found the actual BouncyCastle 1.84 behavior differs from what was originally assumed:
 * the real total-weight ceiling is {@code secret.length} (not 255), and reconstructing from
 * more shares than the threshold requires does NOT silently corrupt the result in this BC
 * version -- both facts are asserted here, not just narrated in a comment.
 */
@RunWith(KeychainTestRunner.class)
public class WeightedShareSplitterTest {

    private static final long MASTER_KEY_ID = 42L;
    private static final String CEREMONY_ID = "ceremony-1";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void reconstructFromExactlyThresholdWeight_returnsCorrectSecret() throws Exception {
        byte[] secret = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2), TrusteeWeight.create("Carol", 1));
        int threshold = 3;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);

        // Alice (weight 2) + Carol (weight 1) = exactly threshold 3
        byte[] recovered = WeightedShareReconstructor.reconstruct(
                Arrays.asList(bundles.get(0), bundles.get(2)), threshold, MASTER_KEY_ID, CEREMONY_ID);

        assertArrayEquals(secret, recovered);
    }

    @Test
    public void weightOneBelowThreshold_throwsInsufficientWeightBeforeTouchingBc() throws Exception {
        byte[] secret = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2));
        int threshold = 3;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);

        // Alice alone has weight 2, one short of threshold 3
        InsufficientWeightException thrown = assertThrows(InsufficientWeightException.class, () ->
                WeightedShareReconstructor.reconstruct(
                        Arrays.asList(bundles.get(0)), threshold, MASTER_KEY_ID, CEREMONY_ID));

        assertEquals(2, thrown.contributedWeight);
        assertEquals(3, thrown.requiredWeight);
    }

    @Test
    public void weightStrictlyGreaterThanThreshold_stillReturnsCorrectSecret() throws Exception {
        // The mandatory regression test for the originally-assumed "truncate to exactly m or get
        // silently wrong bytes" landmine -- empirically, this BC version does NOT exhibit that
        // landmine (see WeightedShareSplitter's class doc), so weight > threshold must match the
        // exact-threshold case byte-for-byte, not merely "not crash."
        byte[] secret = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2), TrusteeWeight.create("Carol", 2));
        int threshold = 3;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);

        // all three trustees contribute: weight 6, well above threshold 3
        byte[] recoveredWithSurplus = WeightedShareReconstructor.reconstruct(bundles, threshold, MASTER_KEY_ID, CEREMONY_ID);
        byte[] recoveredAtExactThreshold = WeightedShareReconstructor.reconstruct(
                Arrays.asList(bundles.get(0), bundles.get(2)), threshold, MASTER_KEY_ID, CEREMONY_ID);

        assertArrayEquals(secret, recoveredWithSurplus);
        assertArrayEquals("surplus-weight reconstruction must match exact-threshold reconstruction byte-for-byte",
                recoveredAtExactThreshold, recoveredWithSurplus);
    }

    @Test
    public void duplicateShare_doesNotDoubleCountWeight() throws Exception {
        byte[] secret = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2));
        int threshold = 3;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);

        // Alice's bundle submitted twice: raw "share count" would look like weight 4, but
        // distinct r-indices are still only 2.
        InsufficientWeightException thrown = assertThrows(InsufficientWeightException.class, () ->
                WeightedShareReconstructor.reconstruct(
                        Arrays.asList(bundles.get(0), bundles.get(0)), threshold, MASTER_KEY_ID, CEREMONY_ID));

        assertEquals("a duplicate share must not count twice toward weight", 2, thrown.contributedWeight);
    }

    @Test
    public void tamperedShare_reconstructsToDifferentBytes() throws Exception {
        byte[] secret = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2));
        int threshold = 3;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);

        TrusteeShareBundle tampered = tamperFirstByte(bundles.get(0));
        byte[] recovered = WeightedShareReconstructor.reconstruct(
                Arrays.asList(tampered, bundles.get(1)), threshold, MASTER_KEY_ID, CEREMONY_ID);

        assertFalse("a tampered share must not silently reconstruct the correct secret",
                Arrays.equals(secret, recovered));
    }

    @Test
    public void wrongCeremonyShare_rejectedByBinderCheckBeforeGfArithmetic() throws Exception {
        byte[] secretA = randomSecret(16);
        byte[] secretB = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 2), TrusteeWeight.create("Bob", 2));
        int threshold = 3;

        List<TrusteeShareBundle> bundlesA = WeightedShareSplitter.split(
                secretA, trustees, threshold, MASTER_KEY_ID, "ceremony-A", RANDOM);
        List<TrusteeShareBundle> bundlesB = WeightedShareSplitter.split(
                secretB, trustees, threshold, MASTER_KEY_ID, "ceremony-B", RANDOM);

        // Alice's real ceremony-A share plus Bob's share from the unrelated ceremony-B split
        ShareBindingMismatchException thrown = assertThrows(ShareBindingMismatchException.class, () ->
                WeightedShareReconstructor.reconstruct(
                        Arrays.asList(bundlesA.get(0), bundlesB.get(1)), threshold, MASTER_KEY_ID, "ceremony-A"));

        assertEquals("ceremony-A", thrown.expectedCeremonyId);
        assertEquals("ceremony-B", thrown.actualCeremonyId);
    }

    @Test
    public void wrongMasterKeyShare_rejectedByBinderCheck() throws Exception {
        byte[] secret = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(TrusteeWeight.create("Alice", 3));
        int threshold = 3;

        List<TrusteeShareBundle> bundlesForKeyA = WeightedShareSplitter.split(
                secret, trustees, threshold, 111L, CEREMONY_ID, RANDOM);

        assertThrows(ShareBindingMismatchException.class, () ->
                WeightedShareReconstructor.reconstruct(bundlesForKeyA, threshold, 222L, CEREMONY_ID));
    }

    @Test
    public void shareCountSatisfiesThresholdButWeightDoesNot_rejected() throws Exception {
        // 3 low-weight trustees hand over 3 bundles (raw count == threshold), but each is
        // weight 1 while the threshold requires weight 4 -- must fail on summed weight, not on
        // "did we get at least `threshold` bundles/shares."
        byte[] secret = randomSecret(16);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 1), TrusteeWeight.create("Bob", 1),
                TrusteeWeight.create("Carol", 1), TrusteeWeight.create("Dave", 1));
        int threshold = 4;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);

        InsufficientWeightException thrown = assertThrows(InsufficientWeightException.class, () ->
                WeightedShareReconstructor.reconstruct(
                        bundles.subList(0, 3), threshold, MASTER_KEY_ID, CEREMONY_ID));

        assertEquals(3, thrown.contributedWeight);
        assertEquals(4, thrown.requiredWeight);
    }

    @Test
    public void totalWeightExceedingSecretLength_rejectedWithCleanException() {
        // Empirically-determined cap (see class doc): resplit(secret, m, n) throws an unchecked
        // ArrayIndexOutOfBoundsException once n exceeds secret.length. This must be caught by
        // WeightedShareSplitter's own upfront validation, never surfaced as that crash.
        byte[] secret = randomSecret(8);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 5), TrusteeWeight.create("Bob", 4)); // totalWeight=9 > 8

        TotalWeightExceedsCapacityException thrown = assertThrows(TotalWeightExceedsCapacityException.class,
                () -> WeightedShareSplitter.split(secret, trustees, 3, MASTER_KEY_ID, CEREMONY_ID, RANDOM));

        assertEquals(9, thrown.requestedTotalWeight);
        assertEquals(8, thrown.maxTotalWeight);
    }

    @Test
    public void totalWeightAtExactSecretLength_splitsAndReconstructsCorrectly() throws Exception {
        // The boundary itself (n == secret.length, not one past it) must work.
        byte[] secret = randomSecret(8);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 4), TrusteeWeight.create("Bob", 4)); // totalWeight=8
        int threshold = 5;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);
        byte[] recovered = WeightedShareReconstructor.reconstruct(bundles, threshold, MASTER_KEY_ID, CEREMONY_ID);

        assertArrayEquals(secret, recovered);
    }

    @Test
    public void fortyFourBytePassphraseSecret_splitsUpToItsRealCapacity() throws Exception {
        // The actual application: a Numeric9x4 passphrase (36 digits + 8 separators = 44 bytes).
        // Confirms the real, in-app ceiling is 44, matching the empirical finding, not 255.
        byte[] secret = randomSecret(44);
        List<TrusteeWeight> trustees = Arrays.asList(
                TrusteeWeight.create("Alice", 20), TrusteeWeight.create("Bob", 20), TrusteeWeight.create("Carol", 4));
        int threshold = 25;

        List<TrusteeShareBundle> bundles = split(secret, trustees, threshold);
        byte[] recovered = WeightedShareReconstructor.reconstruct(
                Arrays.asList(bundles.get(0), bundles.get(1)), threshold, MASTER_KEY_ID, CEREMONY_ID);

        assertArrayEquals(secret, recovered);

        TotalWeightExceedsCapacityException thrown = assertThrows(TotalWeightExceedsCapacityException.class,
                () -> WeightedShareSplitter.split(secret,
                        Arrays.asList(TrusteeWeight.create("Everyone", 45)), 3, MASTER_KEY_ID, CEREMONY_ID, RANDOM));
        assertEquals(44, thrown.maxTotalWeight);
    }

    @Test
    public void reconstructWithNoBundles_throwsInsufficientWeight() {
        assertThrows(InsufficientWeightException.class, () ->
                WeightedShareReconstructor.reconstruct(new ArrayList<>(), 3, MASTER_KEY_ID, CEREMONY_ID));
    }

    private static List<TrusteeShareBundle> split(byte[] secret, List<TrusteeWeight> trustees, int threshold)
            throws TotalWeightExceedsCapacityException {
        return WeightedShareSplitter.split(secret, trustees, threshold, MASTER_KEY_ID, CEREMONY_ID, RANDOM);
    }

    private static byte[] randomSecret(int length) {
        byte[] secret = new byte[length];
        RANDOM.nextBytes(secret);
        return secret;
    }

    private static TrusteeShareBundle tamperFirstByte(TrusteeShareBundle bundle) {
        List<byte[]> tamperedBytes = new ArrayList<>();
        boolean tamperedOne = false;
        for (byte[] shareBytes : bundle.getShareBytes()) {
            byte[] copy = shareBytes.clone();
            if (!tamperedOne) {
                copy[0] ^= 0xFF;
                tamperedOne = true;
            }
            tamperedBytes.add(copy);
        }
        return TrusteeShareBundle.create(bundle.getTrusteeLabel(), bundle.getShareIndices(), tamperedBytes,
                bundle.getMasterKeyId(), bundle.getCeremonyId(), bundle.getThresholdWeight(), bundle.getTotalWeight());
    }
}
