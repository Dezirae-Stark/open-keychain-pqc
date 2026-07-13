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


import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import android.content.Context;

import org.sufficientlysecure.keychain.KeychainDatabase;
import org.sufficientlysecure.keychain.SocialRecoverySharesQueries;
import org.sufficientlysecure.keychain.Social_recovery_shares;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;


/**
 * Persists social-recovery split-ceremony metadata -- never share material, see
 * SocialRecoveryShares.sq. One row per trustee per ceremony.
 */
public class SocialRecoveryShareDao extends AbstractDao {
    SocialRecoverySharesQueries queries = getDatabase().getSocialRecoverySharesQueries();

    public static SocialRecoveryShareDao create(Context context) {
        KeychainDatabase database = KeychainDatabase.getInstance(context);
        DatabaseNotifyManager databaseNotifyManager = DatabaseNotifyManager.create(context);

        return new SocialRecoveryShareDao(database, databaseNotifyManager);
    }

    private SocialRecoveryShareDao(KeychainDatabase database, DatabaseNotifyManager databaseNotifyManager) {
        super(database, databaseNotifyManager);
    }

    public void recordSplitCeremony(long masterKeyId, String ceremonyId, List<TrusteeShareBundle> trusteeBundles,
            int thresholdWeight, int totalWeight, Date created) {
        for (TrusteeShareBundle bundle : trusteeBundles) {
            queries.insertTrusteeRecord(new Social_recovery_shares(
                    masterKeyId,
                    ceremonyId,
                    bundle.getTrusteeLabel(),
                    joinIndices(bundle.getShareIndices()),
                    (long) bundle.getWeight(),
                    bundle.getShareChecksum(),
                    (long) thresholdWeight,
                    (long) totalWeight,
                    created));
        }
    }

    public List<Social_recovery_shares> getRecordsForMasterKeyId(long masterKeyId) {
        return queries.selectByMasterKeyId(masterKeyId).executeAsList();
    }

    public String getLatestCeremonyId(long masterKeyId) {
        return queries.selectLatestCeremonyId(masterKeyId).executeAsOneOrNull();
    }

    public void deleteCeremony(long masterKeyId, String ceremonyId) {
        queries.deleteByMasterKeyIdAndCeremony(masterKeyId, ceremonyId);
    }

    public void deleteAllForMasterKeyId(long masterKeyId) {
        queries.deleteAllForMasterKeyId(masterKeyId);
    }

    static String joinIndices(List<Integer> indices) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < indices.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(indices.get(i));
        }
        return sb.toString();
    }

    static List<Integer> parseIndices(String csv) {
        List<Integer> indices = new ArrayList<>();
        for (String part : csv.split(",")) {
            indices.add(Integer.parseInt(part.trim()));
        }
        return indices;
    }
}
