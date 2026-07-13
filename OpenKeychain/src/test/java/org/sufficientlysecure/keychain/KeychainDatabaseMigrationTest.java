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
 * Covers {@link KeychainDatabase#addKeyMetadataProvenanceColumns}, the v36->v37 migration that
 * backs A3's provenance metadata (see KeyMetadata.sq and KeyMetadataDao#recordProvenance).
 * Exercises the actual migration method against a hand-built table matching the real pre-
 * migration (v36) key_metadata shape -- not a reimplementation of the migration logic -- so this
 * fails if the real method's SQL is ever wrong, not just if some independent copy of the SQL is
 * wrong.
 */
@RunWith(KeychainTestRunner.class)
public class KeychainDatabaseMigrationTest {

    private SQLiteDatabase rawDb;
    private SupportSQLiteDatabase db;

    @Before
    public void setUp() {
        // In-memory database, independent of the app's own KeychainDatabase instance -- this
        // test constructs exactly the v36 key_metadata shape by hand, since there's no v36
        // schema artifact to load from (SQLDelight only generates the *current* schema).
        rawDb = SQLiteDatabase.create(null);
        rawDb.execSQL("CREATE TABLE key_metadata ("
                + "master_key_id INTEGER PRIMARY KEY, "
                + "last_updated INTEGER, "
                + "seen_on_keyservers INTEGER)");
        rawDb.execSQL("INSERT INTO key_metadata (master_key_id, last_updated, seen_on_keyservers) "
                + "VALUES (123, 1000, 1)");
        db = new FrameworkSQLiteDatabase(rawDb);
    }

    @After
    public void tearDown() {
        rawDb.close();
    }

    @Test
    public void migration_preservesExistingRowData() {
        KeychainDatabase.getInstance(RuntimeEnvironment.getApplication()).addKeyMetadataProvenanceColumns(db);

        try (Cursor cursor = rawDb.rawQuery(
                "SELECT master_key_id, last_updated, seen_on_keyservers FROM key_metadata WHERE master_key_id = 123",
                null)) {
            assertTrue("pre-existing row must survive the migration", cursor.moveToFirst());
            assertEquals(123, cursor.getLong(0));
            assertEquals(1000, cursor.getLong(1));
            assertEquals(1, cursor.getInt(2));
        }
    }

    @Test
    public void migration_newColumnsAreNullForPreExistingRows() {
        KeychainDatabase.getInstance(RuntimeEnvironment.getApplication()).addKeyMetadataProvenanceColumns(db);

        try (Cursor cursor = rawDb.rawQuery(
                "SELECT generated_by_app_version, entropy_source, provenance_schema_version "
                        + "FROM key_metadata WHERE master_key_id = 123",
                null)) {
            assertTrue(cursor.moveToFirst());
            assertTrue("generated_by_app_version must be NULL, not backfilled", cursor.isNull(0));
            assertTrue("entropy_source must be NULL, not backfilled", cursor.isNull(1));
            assertTrue("provenance_schema_version must be NULL, not backfilled", cursor.isNull(2));
        }
    }

    @Test
    public void migration_newColumnsAreWritableAfterward() {
        KeychainDatabase.getInstance(RuntimeEnvironment.getApplication()).addKeyMetadataProvenanceColumns(db);

        rawDb.execSQL("UPDATE key_metadata SET generated_by_app_version = ?, entropy_source = ?, "
                + "provenance_schema_version = ? WHERE master_key_id = 123",
                new Object[]{"6.0.4-pqc.5", "android_securerandom", 1});

        try (Cursor cursor = rawDb.rawQuery(
                "SELECT generated_by_app_version, entropy_source, provenance_schema_version "
                        + "FROM key_metadata WHERE master_key_id = 123",
                null)) {
            assertTrue(cursor.moveToFirst());
            assertEquals("6.0.4-pqc.5", cursor.getString(0));
            assertEquals("android_securerandom", cursor.getString(1));
            assertEquals(1, cursor.getInt(2));
        }
    }

    @Test
    public void migration_insertingANewRowAfterMigrationLeavesProvenanceNullByDefault() {
        KeychainDatabase.getInstance(RuntimeEnvironment.getApplication()).addKeyMetadataProvenanceColumns(db);

        rawDb.execSQL("INSERT INTO key_metadata (master_key_id, last_updated, seen_on_keyservers) "
                + "VALUES (456, 2000, 0)");

        try (Cursor cursor = rawDb.rawQuery(
                "SELECT generated_by_app_version, entropy_source, provenance_schema_version "
                        + "FROM key_metadata WHERE master_key_id = 456",
                null)) {
            assertTrue(cursor.moveToFirst());
            assertTrue(cursor.isNull(0));
            assertTrue(cursor.isNull(1));
            assertTrue(cursor.isNull(2));
        }
    }
}
