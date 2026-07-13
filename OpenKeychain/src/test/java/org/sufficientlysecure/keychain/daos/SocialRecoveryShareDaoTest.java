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

package org.sufficientlysecure.keychain.daos;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.Social_recovery_shares;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(KeychainTestRunner.class)
public class SocialRecoveryShareDaoTest {

    @Test
    public void recordSplitCeremony_persistsOneRowPerTrustee() {
        SocialRecoveryShareDao dao = SocialRecoveryShareDao.create(RuntimeEnvironment.getApplication());
        List<TrusteeShareBundle> bundles = Arrays.asList(
                TrusteeShareBundle.create("Alice", Arrays.asList(1, 2),
                        Arrays.asList(new byte[] { 1 }, new byte[] { 2 }), 42L, "ceremony-1", 2, 3),
                TrusteeShareBundle.create("Bob", Arrays.asList(3),
                        Arrays.asList(new byte[] { 3 }), 42L, "ceremony-1", 2, 3));

        dao.recordSplitCeremony(42L, "ceremony-1", bundles, 2, 3, new Date(1000));

        List<Social_recovery_shares> records = dao.getRecordsForMasterKeyId(42L);
        assertEquals(2, records.size());

        Social_recovery_shares alice = records.get(0).getTrustee_label().equals("Alice") ? records.get(0) : records.get(1);
        assertEquals("1,2", alice.getShare_indices_csv());
        assertEquals(2, alice.getWeight());
        assertEquals(2, alice.getThreshold_weight());
        assertEquals(3, alice.getTotal_weight());
        assertEquals(alice.getShare_checksum(), TrusteeShareBundle.create("Alice", Arrays.asList(1, 2),
                Arrays.asList(new byte[] { 1 }, new byte[] { 2 }), 42L, "ceremony-1", 2, 3).getShareChecksum());
    }

    @Test
    public void getLatestCeremonyId_returnsMostRecentlyCreated() {
        SocialRecoveryShareDao dao = SocialRecoveryShareDao.create(RuntimeEnvironment.getApplication());
        List<TrusteeShareBundle> bundles = Arrays.asList(
                TrusteeShareBundle.create("Alice", Arrays.asList(1), Arrays.asList(new byte[] { 1 }), 42L, "old", 1, 1));
        dao.recordSplitCeremony(42L, "old", bundles, 1, 1, new Date(1000));

        List<TrusteeShareBundle> newerBundles = Arrays.asList(
                TrusteeShareBundle.create("Alice", Arrays.asList(1), Arrays.asList(new byte[] { 9 }), 42L, "new", 1, 1));
        dao.recordSplitCeremony(42L, "new", newerBundles, 1, 1, new Date(2000));

        assertEquals("new", dao.getLatestCeremonyId(42L));
    }

    @Test
    public void deleteCeremony_removesOnlyThatCeremonysRows() {
        SocialRecoveryShareDao dao = SocialRecoveryShareDao.create(RuntimeEnvironment.getApplication());
        dao.recordSplitCeremony(42L, "ceremony-1",
                Arrays.asList(TrusteeShareBundle.create("Alice", Arrays.asList(1), Arrays.asList(new byte[] { 1 }), 42L, "ceremony-1", 1, 1)),
                1, 1, new Date(1000));
        dao.recordSplitCeremony(42L, "ceremony-2",
                Arrays.asList(TrusteeShareBundle.create("Bob", Arrays.asList(1), Arrays.asList(new byte[] { 2 }), 42L, "ceremony-2", 1, 1)),
                1, 1, new Date(2000));

        dao.deleteCeremony(42L, "ceremony-1");

        List<Social_recovery_shares> remaining = dao.getRecordsForMasterKeyId(42L);
        assertEquals(1, remaining.size());
        assertEquals("ceremony-2", remaining.get(0).getCeremony_id());
    }

    @Test
    public void noRecords_returnsEmptyListAndNullLatestCeremony() {
        SocialRecoveryShareDao dao = SocialRecoveryShareDao.create(RuntimeEnvironment.getApplication());

        assertTrue(dao.getRecordsForMasterKeyId(999L).isEmpty());
        assertNull(dao.getLatestCeremonyId(999L));
    }
}
