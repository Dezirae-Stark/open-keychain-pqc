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

package org.sufficientlysecure.keychain.ui.keyview.loader;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.junit.Test;
import org.sufficientlysecure.keychain.Keys;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey.SecretKeyType;
import org.sufficientlysecure.keychain.ui.keyview.loader.SubkeyStatusDao.SubKeyItem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SubkeyStatusDaoStressScoreTest {

    private static final long DAY_SECONDS = 24 * 60 * 60;
    // Arbitrary fixed reference instant -- "now" is an explicit parameter to computeStressScore
    // specifically so tests don't depend on the wall clock at run time.
    private static final long NOW_EPOCH_SECONDS = 1_800_000_000L;
    private static final Date NOW = new Date(NOW_EPOCH_SECONDS * 1000);

    private static final List<SubKeyItem> NO_SUBKEYS = Collections.emptyList();

    @Test
    public void healthyRecentKey_scoresNearZero() {
        SubKeyItem certify = safeKey(1L, NOW_EPOCH_SECONDS - 10 * DAY_SECONDS, null, false);

        double score = SubkeyStatusDao.computeStressScore(certify, NO_SUBKEYS, NO_SUBKEYS, NOW);

        assertTrue("a healthy, recently-created key with no expiry should score near zero, was " + score,
                score < 0.01);
    }

    @Test
    public void certifyKeyExpiringSoon_contributesExpiryComponent() {
        SubKeyItem certify = safeKey(1L, NOW_EPOCH_SECONDS, NOW_EPOCH_SECONDS + 6 * DAY_SECONDS, false);

        double score = SubkeyStatusDao.computeStressScore(certify, NO_SUBKEYS, NO_SUBKEYS, NOW);

        // expiryComponent = 1 - 6/30 = 0.8, weighted by 0.5 => 0.4 exactly (creation == now means
        // zero staleness contribution, no security problem).
        assertEquals(0.4, score, 1e-9);
    }

    @Test
    public void signSubkeyExpiringSoon_alsoContributesExpiryComponent() {
        SubKeyItem certify = safeKey(1L, NOW_EPOCH_SECONDS, null, false);
        SubKeyItem signKey = safeKey(2L, NOW_EPOCH_SECONDS, NOW_EPOCH_SECONDS + 6 * DAY_SECONDS, false);

        double score = SubkeyStatusDao.computeStressScore(certify, list(signKey), NO_SUBKEYS, NOW);

        assertEquals("expiry proximity of a sign subkey must be considered, not just the certify key",
                0.4, score, 1e-9);
    }

    @Test
    public void insecureAlgorithm_contributesSecurityProblemComponent() {
        SubKeyItem certify = insecureKey(1L, NOW_EPOCH_SECONDS);

        double score = SubkeyStatusDao.computeStressScore(certify, NO_SUBKEYS, NO_SUBKEYS, NOW);

        assertEquals(0.3, score, 1e-9);
    }

    @Test
    public void veryOldCertifyKey_contributesStalenessComponentCappedAtOne() {
        SubKeyItem atWindowBoundary = safeKey(1L, NOW_EPOCH_SECONDS - 1095 * DAY_SECONDS, null, false);
        SubKeyItem wellBeyondWindow = safeKey(1L, NOW_EPOCH_SECONDS - 2000 * DAY_SECONDS, null, false);

        double scoreAtBoundary = SubkeyStatusDao.computeStressScore(atWindowBoundary, NO_SUBKEYS, NO_SUBKEYS, NOW);
        double scoreBeyondWindow = SubkeyStatusDao.computeStressScore(wellBeyondWindow, NO_SUBKEYS, NO_SUBKEYS, NOW);

        assertEquals(0.2, scoreAtBoundary, 1e-9);
        assertEquals("staleness must cap at 1.0 rather than growing unbounded", 0.2, scoreBeyondWindow, 1e-9);
    }

    @Test
    public void allThreeFactorsCombine_additively() {
        SubKeyItem certify = insecureKey(1L, NOW_EPOCH_SECONDS - 1095 * DAY_SECONDS);
        // insecureKey has no expiry set; add a sign subkey carrying the expiry-proximity factor.
        SubKeyItem signKey = safeKey(2L, NOW_EPOCH_SECONDS, NOW_EPOCH_SECONDS + 6 * DAY_SECONDS, false);

        double score = SubkeyStatusDao.computeStressScore(certify, list(signKey), NO_SUBKEYS, NOW);

        assertEquals(0.4 + 0.3 + 0.2, score, 1e-9);
    }

    @Test
    public void alreadyExpiredCertifyKey_doesNotContributeExpiryComponent() {
        // Already-expired is covered by the binary EXPIRED KeyHealthStatus elsewhere; the
        // continuous score deliberately doesn't pile on for a key that's already invalid.
        SubKeyItem alreadyExpired = safeKey(1L, NOW_EPOCH_SECONDS, NOW_EPOCH_SECONDS - DAY_SECONDS, false);

        double score = SubkeyStatusDao.computeStressScore(alreadyExpired, NO_SUBKEYS, NO_SUBKEYS, NOW);

        assertEquals(0.0, score, 1e-9);
    }

    private static List<SubKeyItem> list(SubKeyItem item) {
        List<SubKeyItem> items = new ArrayList<>();
        items.add(item);
        return items;
    }

    private static SubKeyItem safeKey(long keyId, long creationEpochSeconds, Long expiryEpochSeconds,
            boolean isRevoked) {
        return new SubKeyItem(keyId, keysOf(keyId, creationEpochSeconds, expiryEpochSeconds, isRevoked,
                PublicKeyAlgorithmTags.RSA_GENERAL, 3072, null));
    }

    private static SubKeyItem insecureKey(long keyId, long creationEpochSeconds) {
        return new SubKeyItem(keyId, keysOf(keyId, creationEpochSeconds, null, false,
                PublicKeyAlgorithmTags.RSA_GENERAL, 1024, null));
    }

    private static Keys keysOf(long keyId, long creationEpochSeconds, Long expiryEpochSeconds,
            boolean isRevoked, int algorithm, int keySize, String curveOid) {
        return new Keys(
                keyId, // master_key_id
                0L, // rank
                keyId, // key_id
                keySize, // key_size
                curveOid, // key_curve_oid
                algorithm, // algorithm
                new byte[20], // fingerprint
                true, // can_certify
                false, // can_sign
                false, // can_encrypt
                false, // can_authenticate
                isRevoked, // is_revoked
                SecretKeyType.PASSPHRASE, // has_secret
                true, // is_secure
                creationEpochSeconds, // creation
                expiryEpochSeconds, // expiry
                creationEpochSeconds // validFrom
        );
    }
}
