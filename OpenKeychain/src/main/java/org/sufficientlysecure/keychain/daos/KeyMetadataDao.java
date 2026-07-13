package org.sufficientlysecure.keychain.daos;


import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import android.content.Context;

import org.sufficientlysecure.keychain.KeyMetadataQueries;
import org.sufficientlysecure.keychain.Key_metadata;
import org.sufficientlysecure.keychain.KeychainDatabase;


public class KeyMetadataDao extends AbstractDao {
    KeyMetadataQueries queries = getDatabase().getKeyMetadataQueries();

    public static KeyMetadataDao create(Context context) {
        KeychainDatabase database = KeychainDatabase.getInstance(context);
        DatabaseNotifyManager databaseNotifyManager = DatabaseNotifyManager.create(context);

        return new KeyMetadataDao(database, databaseNotifyManager);
    }

    private KeyMetadataDao(KeychainDatabase database, DatabaseNotifyManager databaseNotifyManager) {
        super(database, databaseNotifyManager);
    }

    public Key_metadata getKeyMetadata(long masterKeyId) {
        return queries.selectByMasterKeyId(masterKeyId).executeAsOneOrNull();
    }

    public void resetAllLastUpdatedTimes() {
        queries.deleteAllLastUpdatedTimes();
    }

    public void renewKeyLastUpdatedTime(long masterKeyId, boolean seenOnKeyservers) {
        queries.insertIfNotExists(masterKeyId);
        queries.updateLastUpdated(new Date(), seenOnKeyservers, masterKeyId);
        getDatabaseNotifyManager().notifyKeyMetadataChange(masterKeyId);
    }

    /**
     * Records where a key's material actually came from, at the moment it's generated. Called
     * once, from EditKeyOperation right after a newly-created key is saved -- not on every edit,
     * since provenance describes generation, not last-touched state. Uses a column-scoped UPDATE
     * (see KeyMetadata.sq's insertIfNotExists/updateProvenance) rather than a REPLACE, so a
     * later renewKeyLastUpdatedTime call for the same key (which happens on every subsequent
     * certify/import/upload/edit) can never silently wipe this out.
     */
    public void recordProvenance(long masterKeyId, String appVersion, String entropySource) {
        queries.insertIfNotExists(masterKeyId);
        queries.updateProvenance(appVersion, entropySource, 1L, masterKeyId);
        getDatabaseNotifyManager().notifyKeyMetadataChange(masterKeyId);
    }

    public List<byte[]> getFingerprintsForKeysOlderThan(long olderThan, TimeUnit timeUnit) {
        return queries.selectFingerprintsForKeysOlderThan(new Date(timeUnit.toMillis(olderThan)))
                .executeAsList();
    }
}
