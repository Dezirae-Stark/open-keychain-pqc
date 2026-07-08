package org.sufficientlysecure.keychain.shadows;


import android.content.Context;

import androidx.work.WorkManager;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;

import static org.mockito.Mockito.mock;


@Implements(WorkManager.class)
public class ShadowWorkManager {

    @Implementation
    public static WorkManager getInstance() {
        return mock(WorkManager.class);
    }

    // Robolectric only actually instantiates KeychainApplication (and so reaches call sites
    // using this overload, e.g. TemporaryFileProvider#workManagerEnqueueCleanup) when unit
    // tests are configured with includeAndroidResources = true. Without shadowing this overload
    // too, any such test fails with "WorkManager is not initialized properly" before it even
    // gets to run.
    @Implementation
    public static WorkManager getInstance(Context context) {
        return mock(WorkManager.class);
    }

}
