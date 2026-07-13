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

package org.sufficientlysecure.keychain.service;

import android.content.Intent;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.Passphrase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Covers the non-secret cache-expiry metadata mirror added for B1 -- UI code needs a
 * non-blocking way to ask "how long until this passphrase expires" without paying the
 * ACTION_PASSPHRASE_CACHE_GET Messenger round-trip cost getCachedPassphrase() needs when it
 * hands back actual passphrase material.
 */
@RunWith(KeychainTestRunner.class)
public class PassphraseCacheServiceExpiryTest {

    private static final long MASTER_KEY_ID = 12345L;

    @After
    public void tearDown() {
        // Metadata mirror is a static field, shared across tests -- always leave it clean.
        PassphraseCacheService.clearCachedPassphrases(RuntimeEnvironment.getApplication());
        startService(clearAllIntent());
    }

    @Test
    public void notCached_peekReturnsNull() {
        assertNull(PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID));
    }

    @Test
    public void ttlCached_peekReturnsApproximateAbsoluteExpiry() {
        long beforeMillis = System.currentTimeMillis();
        startService(addIntent(300));
        long afterMillis = System.currentTimeMillis();

        Long expiryMillis = PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID);

        assertTrue("must be cached", expiryMillis != null);
        assertTrue("expiry must be at least 300s after the call was made",
                expiryMillis >= beforeMillis + 300_000);
        assertTrue("expiry must be no later than 300s after the call returned",
                expiryMillis <= afterMillis + 300_000);
    }

    @Test
    public void lockModeCached_peekReturnsNoTtlSentinel() {
        startService(addIntent(0));

        Long expiryMillis = PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID);

        assertTrue("must be cached", expiryMillis != null);
        assertTrue(PassphraseCacheService.isNoTtlExpiry(expiryMillis));
    }

    @Test
    public void neverModeCached_peekReturnsNoTtlSentinel() {
        startService(addIntent(Integer.MAX_VALUE));

        Long expiryMillis = PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID);

        assertTrue("must be cached", expiryMillis != null);
        assertTrue(PassphraseCacheService.isNoTtlExpiry(expiryMillis));
    }

    @Test
    public void clearingSpecificKey_removesExpiryMetadataToo() {
        startService(addIntent(300));
        assertTrue(PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID) != null);

        startService(clearSpecificIntent());

        assertNull("clearing the cache entry must also remove the expiry metadata mirror",
                PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID));
    }

    @Test
    public void clearingAllKeys_removesExpiryMetadataToo() {
        startService(addIntent(300));
        assertTrue(PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID) != null);

        startService(clearAllIntent());

        assertNull(PassphraseCacheService.peekCachedPassphraseExpiryMillis(MASTER_KEY_ID));
    }

    private void startService(Intent intent) {
        Robolectric.buildService(PassphraseCacheService.class, intent).create().startCommand(0, 0);
    }

    private Intent addIntent(int ttlSeconds) {
        Intent intent = new Intent(RuntimeEnvironment.getApplication(), PassphraseCacheService.class);
        intent.setAction(PassphraseCacheService.ACTION_PASSPHRASE_CACHE_ADD);
        intent.putExtra(PassphraseCacheService.EXTRA_TTL, ttlSeconds);
        intent.putExtra(PassphraseCacheService.EXTRA_PASSPHRASE, new Passphrase("test"));
        intent.putExtra(PassphraseCacheService.EXTRA_KEY_ID, MASTER_KEY_ID);
        intent.putExtra(PassphraseCacheService.EXTRA_SUBKEY_ID, MASTER_KEY_ID);
        intent.putExtra(PassphraseCacheService.EXTRA_USER_ID, "test user");
        return intent;
    }

    private Intent clearSpecificIntent() {
        Intent intent = new Intent(RuntimeEnvironment.getApplication(), PassphraseCacheService.class);
        intent.setAction(PassphraseCacheService.ACTION_PASSPHRASE_CACHE_CLEAR);
        intent.putExtra(PassphraseCacheService.EXTRA_KEY_ID, MASTER_KEY_ID);
        intent.putExtra(PassphraseCacheService.EXTRA_SUBKEY_ID, MASTER_KEY_ID);
        return intent;
    }

    private Intent clearAllIntent() {
        Intent intent = new Intent(RuntimeEnvironment.getApplication(), PassphraseCacheService.class);
        intent.setAction(PassphraseCacheService.ACTION_PASSPHRASE_CACHE_CLEAR);
        return intent;
    }
}
