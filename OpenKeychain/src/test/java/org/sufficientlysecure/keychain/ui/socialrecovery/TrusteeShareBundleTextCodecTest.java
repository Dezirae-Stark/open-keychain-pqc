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

package org.sufficientlysecure.keychain.ui.socialrecovery;

import java.util.Arrays;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(KeychainTestRunner.class)
public class TrusteeShareBundleTextCodecTest {

    @Test
    public void encodeThenDecode_roundTripsExactly() {
        TrusteeShareBundle original = TrusteeShareBundle.create("Alice ☃ unicode!", Arrays.asList(1, 2),
                Arrays.asList(new byte[] { 1, 2, 3 }, new byte[] { (byte) 0xFF, 0, 5 }), 42L, "ceremony-1", 3, 5);

        String encoded = TrusteeShareBundleTextCodec.encode(original);
        TrusteeShareBundle decoded = TrusteeShareBundleTextCodec.decode(encoded);

        assertEquals(original.getTrusteeLabel(), decoded.getTrusteeLabel());
        assertEquals(original.getWeight(), decoded.getWeight());
        assertEquals(original.getShareIndices(), decoded.getShareIndices());
        assertEquals(original.getMasterKeyId(), decoded.getMasterKeyId());
        assertEquals(original.getCeremonyId(), decoded.getCeremonyId());
        assertEquals(original.getThresholdWeight(), decoded.getThresholdWeight());
        assertEquals(original.getTotalWeight(), decoded.getTotalWeight());
        assertEquals(original.getShareChecksum(), decoded.getShareChecksum());
        for (int i = 0; i < original.getShareBytes().size(); i++) {
            assertArrayEquals(original.getShareBytes().get(i), decoded.getShareBytes().get(i));
        }
    }

    @Test
    public void encodedText_hasRecognizablePrefix() {
        TrusteeShareBundle bundle = TrusteeShareBundle.create(
                "Bob", Arrays.asList(1), Arrays.asList(new byte[] { 9 }), 1L, "c", 1, 1);

        assertTrue(TrusteeShareBundleTextCodec.encode(bundle).startsWith("SRSHARE1:"));
    }

    @Test
    public void decode_garbageText_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> TrusteeShareBundleTextCodec.decode("not a share at all"));
    }

    @Test
    public void decode_truncatedValidPrefix_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> TrusteeShareBundleTextCodec.decode("SRSHARE1:AAAA"));
    }

    @Test
    public void decode_null_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> TrusteeShareBundleTextCodec.decode(null));
    }
}
