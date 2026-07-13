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

package org.sufficientlysecure.keychain.ui.util;

import android.graphics.Bitmap;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(KeychainTestRunner.class)
public class CrystalFingerprintRendererTest {

    private static final byte[] FINGERPRINT_A = fingerprintOf((byte) 0x01, (byte) 0x02, (byte) 0x03);
    private static final byte[] FINGERPRINT_B = fingerprintOf((byte) 0xAA, (byte) 0xBB, (byte) 0xCC);

    @Test
    public void render_sameFingerprintTwice_producesPixelIdenticalBitmaps() {
        Bitmap first = CrystalFingerprintRenderer.render(FINGERPRINT_A, 96);
        Bitmap second = CrystalFingerprintRenderer.render(FINGERPRINT_A, 96);

        assertTrue("rendering the same fingerprint bytes twice must be pixel-identical, "
                + "since this is a deterministic perceptual hash, not a random image",
                first.sameAs(second));
    }

    @Test
    public void seedFrom_differentFingerprints_producesDifferentSeeds() {
        // The rendered Bitmap's pixel content depends on Robolectric's Canvas/Path
        // rasterization fidelity, which isn't guaranteed pixel-exact under the shadow
        // graphics stack -- so uniqueness is verified at the deterministic seed level
        // instead, which is the actual source of all downstream visual difference.
        long seedA = CrystalFingerprintRenderer.seedFrom(FINGERPRINT_A);
        long seedB = CrystalFingerprintRenderer.seedFrom(FINGERPRINT_B);

        assertTrue("different fingerprint bytes must produce different seeds, "
                + "otherwise unrelated keys would render identical crystals",
                seedA != seedB);
    }

    @Test
    public void seedFrom_sameFingerprintTwice_producesSameSeed() {
        long first = CrystalFingerprintRenderer.seedFrom(FINGERPRINT_A);
        long second = CrystalFingerprintRenderer.seedFrom(FINGERPRINT_A);

        assertEquals(first, second);
    }

    @Test
    public void render_returnsBitmapOfRequestedSize() {
        Bitmap bitmap = CrystalFingerprintRenderer.render(FINGERPRINT_A, 128);

        assertEquals(128, bitmap.getWidth());
        assertEquals(128, bitmap.getHeight());
    }

    @Test
    public void render_nullFingerprint_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> CrystalFingerprintRenderer.render(null, 96));
    }

    @Test
    public void render_emptyFingerprint_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> CrystalFingerprintRenderer.render(new byte[0], 96));
    }

    @Test
    public void render_nonPositiveSize_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> CrystalFingerprintRenderer.render(FINGERPRINT_A, 0));
    }

    private static byte[] fingerprintOf(byte... bytes) {
        return bytes;
    }
}
