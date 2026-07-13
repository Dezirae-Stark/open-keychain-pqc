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

/**
 * Maps a continuous 0.0-1.0 signal to one of three stable display buckets, using hysteresis
 * around each threshold so a value oscillating near a boundary doesn't flicker the displayed
 * bucket back and forth -- the bucket only changes once the raw value has moved past the
 * threshold it's crossing by at least the margin, not merely past the threshold itself.
 */
public class DecayingSignal {

    public enum Level {
        LOW, MEDIUM, HIGH
    }

    private DecayingSignal() {
    }

    /**
     * First evaluation of a signal, with no previous bucket to be sticky about.
     */
    public static Level initialLevel(double rawValue, double mediumThreshold, double highThreshold) {
        validate(rawValue, mediumThreshold, highThreshold, 0.0);

        if (rawValue >= highThreshold) {
            return Level.HIGH;
        }
        if (rawValue >= mediumThreshold) {
            return Level.MEDIUM;
        }
        return Level.LOW;
    }

    /**
     * Subsequent evaluation of a signal that already has a displayed bucket. The bucket only
     * moves once {@code rawValue} has crossed the relevant threshold by at least
     * {@code hysteresisMargin}; marginal movement near a boundary leaves the previous bucket
     * displayed.
     */
    public static Level nextLevel(Level previousLevel, double rawValue, double mediumThreshold,
            double highThreshold, double hysteresisMargin) {
        validate(rawValue, mediumThreshold, highThreshold, hysteresisMargin);

        switch (previousLevel) {
            case LOW:
                if (rawValue >= mediumThreshold + hysteresisMargin) {
                    return rawValue >= highThreshold + hysteresisMargin ? Level.HIGH : Level.MEDIUM;
                }
                return Level.LOW;
            case MEDIUM:
                if (rawValue >= highThreshold + hysteresisMargin) {
                    return Level.HIGH;
                }
                if (rawValue < mediumThreshold - hysteresisMargin) {
                    return Level.LOW;
                }
                return Level.MEDIUM;
            case HIGH:
                if (rawValue < highThreshold - hysteresisMargin) {
                    return rawValue < mediumThreshold - hysteresisMargin ? Level.LOW : Level.MEDIUM;
                }
                return Level.HIGH;
            default:
                throw new IllegalStateException("unreachable: " + previousLevel);
        }
    }

    private static void validate(double rawValue, double mediumThreshold, double highThreshold,
            double hysteresisMargin) {
        if (rawValue < 0.0 || rawValue > 1.0) {
            throw new IllegalArgumentException("rawValue must be in [0.0, 1.0], was " + rawValue);
        }
        if (!(mediumThreshold < highThreshold)) {
            throw new IllegalArgumentException("mediumThreshold must be less than highThreshold");
        }
        if (hysteresisMargin < 0.0) {
            throw new IllegalArgumentException("hysteresisMargin must not be negative");
        }
    }
}
