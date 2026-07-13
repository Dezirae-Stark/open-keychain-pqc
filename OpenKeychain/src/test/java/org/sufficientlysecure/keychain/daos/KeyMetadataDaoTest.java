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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.Key_metadata;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Covers {@link KeyMetadataDao#recordProvenance} and {@link KeyMetadataDao#renewKeyLastUpdatedTime},
 * specifically the invariant that motivated splitting key_metadata's writes into column-scoped
 * UPDATEs (see KeyMetadata.sq): calling one must never clobber data written by the other, since
 * renewKeyLastUpdatedTime runs on every certify/import/upload/edit of a key that already has
 * provenance recorded from its original creation.
 */
@RunWith(KeychainTestRunner.class)
public class KeyMetadataDaoTest {

    private static final long MASTER_KEY_ID = 123L;

    private KeyMetadataDao dao;

    @Before
    public void setUp() {
        // key_metadata is explicitly not FK-bound to keyrings_public (see KeyMetadata.sq), so
        // no real keyring needs to exist for masterKeyId here.
        dao = KeyMetadataDao.create(RuntimeEnvironment.getApplication());
    }

    @Test
    public void recordProvenance_thenRenewLastUpdated_provenanceSurvives() {
        dao.recordProvenance(MASTER_KEY_ID, "6.0.4-pqc.5", "android_securerandom");
        dao.renewKeyLastUpdatedTime(MASTER_KEY_ID, true);

        Key_metadata metadata = dao.getKeyMetadata(MASTER_KEY_ID);
        assertNotNull(metadata);
        assertEquals("6.0.4-pqc.5", metadata.getGenerated_by_app_version());
        assertEquals("android_securerandom", metadata.getEntropy_source());
        assertNotNull(metadata.getLast_updated());
        assertTrue(metadata.getSeen_on_keyservers());
    }

    @Test
    public void renewLastUpdated_thenRecordProvenance_lastUpdatedSurvives() {
        dao.renewKeyLastUpdatedTime(MASTER_KEY_ID, true);
        dao.recordProvenance(MASTER_KEY_ID, "6.0.4-pqc.5", "android_securerandom");

        Key_metadata metadata = dao.getKeyMetadata(MASTER_KEY_ID);
        assertNotNull(metadata);
        assertNotNull("last_updated must survive a later recordProvenance call", metadata.getLast_updated());
        assertTrue("seen_on_keyservers must survive a later recordProvenance call", metadata.getSeen_on_keyservers());
        assertEquals("6.0.4-pqc.5", metadata.getGenerated_by_app_version());
    }

    @Test
    public void recordProvenance_thenRenewLastUpdatedTwice_provenanceStillSurvives() {
        // The actual real-world scenario: a key is created (provenance recorded once), then
        // certified/imported/uploaded/edited multiple times afterward (each calling
        // renewKeyLastUpdatedTime). Provenance describes generation and must not decay.
        dao.recordProvenance(MASTER_KEY_ID, "6.0.4-pqc.5", "android_securerandom");
        dao.renewKeyLastUpdatedTime(MASTER_KEY_ID, true);
        dao.renewKeyLastUpdatedTime(MASTER_KEY_ID, false);

        Key_metadata metadata = dao.getKeyMetadata(MASTER_KEY_ID);
        assertNotNull(metadata);
        assertEquals("6.0.4-pqc.5", metadata.getGenerated_by_app_version());
        assertEquals("android_securerandom", metadata.getEntropy_source());
    }

    @Test
    public void getKeyMetadata_beforeAnyWrite_isNull() {
        assertNull(dao.getKeyMetadata(MASTER_KEY_ID));
    }
}
