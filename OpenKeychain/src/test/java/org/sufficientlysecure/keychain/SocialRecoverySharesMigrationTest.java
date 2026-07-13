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

package org.sufficientlysecure.keychain;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import androidx.sqlite.db.SupportSQLiteDatabase;
import androidx.sqlite.db.framework.FrameworkSQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Covers {@link KeychainDatabase#createSocialRecoverySharesTable}, the v37->v38 migration
 * backing B7's persisted split-ceremony metadata (see SocialRecoveryShares.sq).
 */
@RunWith(KeychainTestRunner.class)
public class SocialRecoverySharesMigrationTest {

    private SQLiteDatabase rawDb;
    private SupportSQLiteDatabase db;

    @Before
    public void setUp() {
        rawDb = SQLiteDatabase.create(null);
        db = new FrameworkSQLiteDatabase(rawDb);
    }

    @After
    public void tearDown() {
        rawDb.close();
    }

    @Test
    public void migration_createsTableWritableWithExpectedColumns() {
        KeychainDatabase.getInstance(RuntimeEnvironment.getApplication()).createSocialRecoverySharesTable(db);

        rawDb.execSQL("INSERT INTO social_recovery_shares (master_key_id, ceremony_id, trustee_label, "
                        + "share_indices_csv, weight, share_checksum, threshold_weight, total_weight, created) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                new Object[] { 123L, "ceremony-1", "Alice", "1,2", 2L, "deadbeef", 3L, 5L, 1000L });

        try (Cursor cursor = rawDb.rawQuery("SELECT master_key_id, ceremony_id, trustee_label, "
                + "share_indices_csv, weight, share_checksum, threshold_weight, total_weight, created "
                + "FROM social_recovery_shares WHERE master_key_id = 123", null)) {
            assertTrue(cursor.moveToFirst());
            assertEquals(123, cursor.getLong(0));
            assertEquals("ceremony-1", cursor.getString(1));
            assertEquals("Alice", cursor.getString(2));
            assertEquals("1,2", cursor.getString(3));
            assertEquals(2, cursor.getInt(4));
            assertEquals("deadbeef", cursor.getString(5));
            assertEquals(3, cursor.getInt(6));
            assertEquals(5, cursor.getInt(7));
            assertEquals(1000, cursor.getLong(8));
        }
    }

    @Test
    public void migration_isIdempotent_calledTwiceDoesNotThrow() {
        KeychainDatabase database = KeychainDatabase.getInstance(RuntimeEnvironment.getApplication());
        database.createSocialRecoverySharesTable(db);
        database.createSocialRecoverySharesTable(db);
    }

    @Test
    public void migration_primaryKeyPreventsDuplicateTrusteeRowForSameCeremony() {
        KeychainDatabase.getInstance(RuntimeEnvironment.getApplication()).createSocialRecoverySharesTable(db);

        rawDb.execSQL("INSERT INTO social_recovery_shares (master_key_id, ceremony_id, trustee_label, "
                        + "share_indices_csv, weight, share_checksum, threshold_weight, total_weight, created) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                new Object[] { 123L, "ceremony-1", "Alice", "1,2", 2L, "deadbeef", 3L, 5L, 1000L });

        try {
            rawDb.execSQL("INSERT INTO social_recovery_shares (master_key_id, ceremony_id, trustee_label, "
                            + "share_indices_csv, weight, share_checksum, threshold_weight, total_weight, created) "
                            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    new Object[] { 123L, "ceremony-1", "Alice", "3,4", 2L, "cafef00d", 3L, 5L, 2000L });
            org.junit.Assert.fail("inserting a second row for the same (master_key_id, ceremony_id, "
                    + "trustee_label) must violate the primary key");
        } catch (android.database.sqlite.SQLiteConstraintException expected) {
            // expected
        }
    }
}
