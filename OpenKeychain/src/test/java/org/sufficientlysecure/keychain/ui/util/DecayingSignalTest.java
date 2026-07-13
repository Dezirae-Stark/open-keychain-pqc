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

import org.junit.Test;
import org.sufficientlysecure.keychain.ui.util.DecayingSignal.Level;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class DecayingSignalTest {

    @Test
    public void initialLevel_belowMediumThreshold_isLow() {
        assertEquals(Level.LOW, DecayingSignal.initialLevel(0.1, 0.4, 0.7));
    }

    @Test
    public void initialLevel_atMediumThreshold_isMedium() {
        assertEquals(Level.MEDIUM, DecayingSignal.initialLevel(0.4, 0.4, 0.7));
    }

    @Test
    public void initialLevel_atHighThreshold_isHigh() {
        assertEquals(Level.HIGH, DecayingSignal.initialLevel(0.7, 0.4, 0.7));
    }

    @Test
    public void nextLevel_marginalMovementWithinHysteresis_staysAtPreviousLevel() {
        // previous level LOW, threshold is 0.4, margin 0.05: 0.42 is past the raw threshold
        // but not past threshold + margin, so this must NOT flicker up to MEDIUM.
        Level result = DecayingSignal.nextLevel(Level.LOW, 0.42, 0.4, 0.7, 0.05);

        assertEquals("marginal crossing within the hysteresis margin must not change the bucket",
                Level.LOW, result);
    }

    @Test
    public void nextLevel_movementPastHysteresisMargin_advancesLevel() {
        Level result = DecayingSignal.nextLevel(Level.LOW, 0.46, 0.4, 0.7, 0.05);

        assertEquals(Level.MEDIUM, result);
    }

    @Test
    public void nextLevel_droppingBackPastHysteresisMargin_returnsToPreviousLevel() {
        Level afterAdvance = DecayingSignal.nextLevel(Level.LOW, 0.46, 0.4, 0.7, 0.05);
        // mediumThreshold - margin = 0.35, so 0.3 is clearly past the drop-back margin.
        Level afterDrop = DecayingSignal.nextLevel(afterAdvance, 0.3, 0.4, 0.7, 0.05);

        assertEquals(Level.MEDIUM, afterAdvance);
        assertEquals(Level.LOW, afterDrop);
    }

    @Test
    public void nextLevel_oscillatingNearBoundary_neverFlickers() {
        // Simulates a jittery raw signal hovering right around the 0.4 boundary. With a 0.05
        // margin, none of these should be enough to move off the initial LOW bucket.
        Level level = Level.LOW;
        double[] jitter = { 0.39, 0.41, 0.38, 0.42, 0.40, 0.41 };
        for (double value : jitter) {
            level = DecayingSignal.nextLevel(level, value, 0.4, 0.7, 0.05);
            assertEquals("jitter within the hysteresis band must not flicker the bucket",
                    Level.LOW, level);
        }
    }

    @Test
    public void rawValueOutOfRange_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> DecayingSignal.initialLevel(1.5, 0.4, 0.7));
        assertThrows(IllegalArgumentException.class,
                () -> DecayingSignal.initialLevel(-0.1, 0.4, 0.7));
    }

    @Test
    public void mediumThresholdNotLessThanHighThreshold_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> DecayingSignal.initialLevel(0.5, 0.7, 0.4));
    }

    @Test
    public void negativeHysteresisMargin_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> DecayingSignal.nextLevel(Level.LOW, 0.5, 0.4, 0.7, -0.01));
    }
}
