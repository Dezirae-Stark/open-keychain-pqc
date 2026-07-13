/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
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

package org.sufficientlysecure.keychain.ui.keyview.loader;


import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import android.content.Context;

import androidx.annotation.NonNull;
import org.sufficientlysecure.keychain.Keys;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey.SecretKeyType;
import org.sufficientlysecure.keychain.pgp.PgpSecurityConstants;
import org.sufficientlysecure.keychain.pgp.SecurityProblem.KeySecurityProblem;


public class SubkeyStatusDao {
    private final KeyRepository keyRepository;


    public static SubkeyStatusDao getInstance(Context context) {
        KeyRepository keyRepository = KeyRepository.create(context);
        return new SubkeyStatusDao(keyRepository);
    }

    private SubkeyStatusDao(KeyRepository keyRepository) {
        this.keyRepository = keyRepository;
    }

    public KeySubkeyStatus getSubkeyStatus(long masterKeyId) {
        SubKeyItem keyCertify = null;
        ArrayList<SubKeyItem> keysSign = new ArrayList<>();
        ArrayList<SubKeyItem> keysEncrypt = new ArrayList<>();
        for (Keys subKey : keyRepository.getSubKeysByMasterKeyId(masterKeyId)) {
            SubKeyItem ski = new SubKeyItem(masterKeyId, subKey);

            if (ski.mKeyId == masterKeyId) {
                keyCertify = ski;
            }

            if (ski.mCanSign) {
                keysSign.add(ski);
            }
            if (ski.mCanEncrypt) {
                keysEncrypt.add(ski);
            }
        }

        if (keyCertify == null) {
            if (!keysSign.isEmpty() || !keysEncrypt.isEmpty()) {
                throw new IllegalStateException("Certification key can't be missing for a key that hasn't been deleted!");
            }
            return null;
        }

        Collections.sort(keysSign, SUBKEY_COMPARATOR);
        Collections.sort(keysEncrypt, SUBKEY_COMPARATOR);

        KeyHealthStatus keyHealthStatus = determineKeyHealthStatus(keyCertify, keysSign, keysEncrypt);

        return new KeySubkeyStatus(keyCertify, keysSign, keysEncrypt, keyHealthStatus);
    }

    private KeyHealthStatus determineKeyHealthStatus(SubKeyItem keyCertify,
            ArrayList<SubKeyItem> keysSign,
            ArrayList<SubKeyItem> keysEncrypt) {
        if (keyCertify.mIsRevoked) {
            return KeyHealthStatus.REVOKED;
        }

        if (keyCertify.mIsExpired) {
            return KeyHealthStatus.EXPIRED;
        }

        if (keyCertify.mSecurityProblem != null) {
            return KeyHealthStatus.INSECURE;
        }

        if (!keysSign.isEmpty() && keysEncrypt.isEmpty()) {
            SubKeyItem keySign = keysSign.get(0);
            if (!keySign.isValid()) {
                return KeyHealthStatus.BROKEN;
            }

            if (keySign.mSecurityProblem != null) {
                return KeyHealthStatus.INSECURE;
            }

            return KeyHealthStatus.SIGN_ONLY;
        }

        if (keysSign.isEmpty() || keysEncrypt.isEmpty()) {
            return KeyHealthStatus.BROKEN;
        }

        SubKeyItem keySign = keysSign.get(0);
        SubKeyItem keyEncrypt = keysEncrypt.get(0);

        if (keySign.mSecurityProblem != null && keySign.isValid()
                || keyEncrypt.mSecurityProblem != null && keyEncrypt.isValid()) {
            return KeyHealthStatus.INSECURE;
        }

        if (!keySign.isValid() || !keyEncrypt.isValid()) {
            return KeyHealthStatus.BROKEN;
        }

        if (keyCertify.mSecretKeyType == SecretKeyType.GNU_DUMMY
                && keySign.mSecretKeyType == SecretKeyType.GNU_DUMMY
                && keyEncrypt.mSecretKeyType == SecretKeyType.GNU_DUMMY) {
            return KeyHealthStatus.STRIPPED;
        }

        if (keyCertify.mSecretKeyType == SecretKeyType.DIVERT_TO_CARD
                && keySign.mSecretKeyType == SecretKeyType.DIVERT_TO_CARD
                && keyEncrypt.mSecretKeyType == SecretKeyType.DIVERT_TO_CARD) {
            return KeyHealthStatus.DIVERT;
        }

        boolean containsDivertKeys = keyCertify.mSecretKeyType == SecretKeyType.DIVERT_TO_CARD ||
                keySign.mSecretKeyType == SecretKeyType.DIVERT_TO_CARD ||
                keyEncrypt.mSecretKeyType == SecretKeyType.DIVERT_TO_CARD;
        if (containsDivertKeys) {
            return KeyHealthStatus.DIVERT_PARTIAL;
        }

        boolean containsStrippedKeys = keyCertify.mSecretKeyType == SecretKeyType.GNU_DUMMY
                || keySign.mSecretKeyType == SecretKeyType.GNU_DUMMY
                || keyEncrypt.mSecretKeyType == SecretKeyType.GNU_DUMMY;
        if (containsStrippedKeys) {
            return KeyHealthStatus.PARTIAL_STRIPPED;
        }

        return KeyHealthStatus.OK;
    }

    private static final long WARNING_WINDOW_DAYS = 30;
    private static final long STALENESS_WINDOW_DAYS = 365 * 3;
    private static final double EXPIRY_WEIGHT = 0.5;
    private static final double SECURITY_PROBLEM_WEIGHT = 0.3;
    private static final double STALENESS_WEIGHT = 0.2;

    /**
     * A continuous 0.0-1.0 "stress" score for a key, additive to (not a replacement for) the
     * binary {@link KeyHealthStatus} above. Where the binary status only flips once a key is
     * already expired/insecure/broken, this score rises smoothly as a key approaches that state
     * -- an early-warning signal for a key that's still nominally OK but trending toward trouble.
     * {@code now} is an explicit parameter (rather than reading the wall clock internally) so
     * this stays a pure, deterministically testable function.
     */
    public static double computeStressScore(SubKeyItem certify, List<SubKeyItem> sign,
            List<SubKeyItem> encrypt, Date now) {
        double expiryComponent = expiryProximityComponent(certify, sign, encrypt, now);
        double securityComponent = hasUnresolvedSecurityProblem(certify, sign, encrypt) ? 1.0 : 0.0;
        double stalenessComponent = stalenessComponent(certify, now);

        double weighted = EXPIRY_WEIGHT * expiryComponent
                + SECURITY_PROBLEM_WEIGHT * securityComponent
                + STALENESS_WEIGHT * stalenessComponent;

        return Math.max(0.0, Math.min(1.0, weighted));
    }

    private static double expiryProximityComponent(SubKeyItem certify, List<SubKeyItem> sign,
            List<SubKeyItem> encrypt, Date now) {
        double worst = 0.0;
        worst = Math.max(worst, expiryProximityOf(certify, now));
        if (!sign.isEmpty()) {
            worst = Math.max(worst, expiryProximityOf(sign.get(0), now));
        }
        if (!encrypt.isEmpty()) {
            worst = Math.max(worst, expiryProximityOf(encrypt.get(0), now));
        }
        return worst;
    }

    private static double expiryProximityOf(SubKeyItem key, Date now) {
        if (key == null || key.mExpiry == null || !key.isValid()) {
            return 0.0;
        }
        long daysUntilExpiry = (key.mExpiry.getTime() - now.getTime()) / (24L * 60 * 60 * 1000);
        if (daysUntilExpiry <= 0 || daysUntilExpiry >= WARNING_WINDOW_DAYS) {
            return 0.0;
        }
        return 1.0 - ((double) daysUntilExpiry / WARNING_WINDOW_DAYS);
    }

    private static boolean hasUnresolvedSecurityProblem(SubKeyItem certify, List<SubKeyItem> sign,
            List<SubKeyItem> encrypt) {
        if (certify.mSecurityProblem != null && certify.isValid()) {
            return true;
        }
        if (!sign.isEmpty() && sign.get(0).mSecurityProblem != null && sign.get(0).isValid()) {
            return true;
        }
        return !encrypt.isEmpty() && encrypt.get(0).mSecurityProblem != null && encrypt.get(0).isValid();
    }

    private static double stalenessComponent(SubKeyItem certify, Date now) {
        long ageDays = (now.getTime() - certify.mCreation.getTime()) / (24L * 60 * 60 * 1000);
        if (ageDays <= 0) {
            return 0.0;
        }
        return Math.min((double) ageDays / STALENESS_WINDOW_DAYS, 1.0);
    }

    public enum KeyHealthStatus {
        OK, DIVERT, DIVERT_PARTIAL, REVOKED, EXPIRED, INSECURE, SIGN_ONLY, STRIPPED, PARTIAL_STRIPPED, BROKEN
    }

    public static class KeySubkeyStatus {
        @NonNull
        public final SubKeyItem keyCertify;
        public final List<SubKeyItem> keysSign;
        public final List<SubKeyItem> keysEncrypt;
        public final KeyHealthStatus keyHealthStatus;

        KeySubkeyStatus(@NonNull SubKeyItem keyCertify, List<SubKeyItem> keysSign, List<SubKeyItem> keysEncrypt,
                KeyHealthStatus keyHealthStatus) {
            this.keyCertify = keyCertify;
            this.keysSign = keysSign;
            this.keysEncrypt = keysEncrypt;
            this.keyHealthStatus = keyHealthStatus;
        }
    }

    public static class SubKeyItem {
        final long mKeyId;
        final Date mCreation;
        public final SecretKeyType mSecretKeyType;
        public final boolean mIsRevoked, mIsExpired;
        public final Date mExpiry;
        final boolean mCanCertify, mCanSign, mCanEncrypt;
        public final KeySecurityProblem mSecurityProblem;

        SubKeyItem(long masterKeyId, Keys subKey) {
            mKeyId = subKey.getKey_id();
            mCreation = new Date(subKey.getCreation() * 1000);

            mSecretKeyType = subKey.getHas_secret();

            mIsRevoked = subKey.is_revoked();
            mExpiry = subKey.getExpiry() == null ? null : new Date(subKey.getExpiry() * 1000);
            mIsExpired = mExpiry != null && mExpiry.before(new Date());

            mCanCertify = subKey.getCan_certify();
            mCanSign = subKey.getCan_sign();
            mCanEncrypt = subKey.getCan_encrypt();

            int algorithm = subKey.getAlgorithm();
            Integer bitStrength = subKey.getKey_size();
            String curveOid = subKey.getKey_curve_oid();

            mSecurityProblem = PgpSecurityConstants.getKeySecurityProblem(
                    masterKeyId, mKeyId, algorithm, bitStrength, curveOid);
        }

        public boolean newerThan(SubKeyItem other) {
            return mCreation.after(other.mCreation);
        }

        public boolean isValid() {
            return !mIsRevoked && !mIsExpired;
        }
    }

    private static final Comparator<SubKeyItem> SUBKEY_COMPARATOR = (one, two) -> {
        if (one == two) {
            return 0;
        }
        // if one is valid and the other isn't, the valid one always comes first
        if (one.isValid() ^ two.isValid()) {
            return one.isValid() ? -1 : 1;
        }
        // compare usability, if one is "more usable" than the other, that one comes first
        int usability = one.mSecretKeyType.compareUsability(two.mSecretKeyType);
        if (usability != 0) {
            return usability;
        }
        if ((one.mSecurityProblem == null) ^ (two.mSecurityProblem == null)) {
            return one.mSecurityProblem == null ? -1 : 1;
        }
        // otherwise, the newer one comes first
        return one.newerThan(two) ? -1 : 1;
    };
}
