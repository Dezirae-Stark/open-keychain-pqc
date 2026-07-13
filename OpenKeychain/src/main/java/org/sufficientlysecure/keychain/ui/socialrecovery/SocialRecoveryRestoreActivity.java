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

package org.sufficientlysecure.keychain.ui.socialrecovery;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.operations.results.SocialRecoveryReconstructResult;
import org.sufficientlysecure.keychain.service.SocialRecoveryReconstructParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;
import org.sufficientlysecure.keychain.ui.base.CryptoOperationHelper;
import org.sufficientlysecure.keychain.ui.keyview.ViewKeyActivity;

/**
 * Minimal, functional restore screen for B7: select the encrypted backup file, paste trustee
 * shares in one at a time (matching the plain-text distribution format from setup), attempt
 * recovery once contributed weight looks sufficient -- final validation happens in
 * {@code SocialRecoveryReconstructOperation} itself.
 */
public class SocialRecoveryRestoreActivity extends AppCompatActivity {
    private static final int REQUEST_SELECT_BACKUP_FILE = 1;

    private long masterKeyId;

    private TextView backupFileStatus;
    private EditText pasteShareInput;
    private TextView weightProgressText;
    private LinearLayout addedSharesContainer;
    private Button attemptRecoveryButton;

    private byte[] backupBytes;
    private final List<TrusteeShareBundle> addedShares = new ArrayList<>();

    private CryptoOperationHelper<SocialRecoveryReconstructParcel, SocialRecoveryReconstructResult> opHelper;

    /**
     * Standalone entry point -- no key context needed, since the whole point of this feature is
     * recovering when local key data (and possibly the whole device) has been lost. The key
     * being recovered is derived from the first trustee share the user adds, not passed in.
     */
    public static Intent createIntent(android.content.Context context) {
        return new Intent(context, SocialRecoveryRestoreActivity.class);
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_social_recovery_restore);

        // -1 means "not yet known" -- set from the first added share's own masterKeyId, since a
        // share is self-describing (see TrusteeShareBundle's class doc) and this screen may be
        // reached with no prior local key context at all.
        masterKeyId = -1;

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.social_recovery_restore_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        backupFileStatus = findViewById(R.id.backup_file_status);
        pasteShareInput = findViewById(R.id.paste_share_input);
        weightProgressText = findViewById(R.id.weight_progress_text);
        addedSharesContainer = findViewById(R.id.added_shares_container);
        attemptRecoveryButton = findViewById(R.id.attempt_recovery_button);

        findViewById(R.id.select_backup_file_button).setOnClickListener(v -> selectBackupFile());
        findViewById(R.id.add_share_button).setOnClickListener(v -> addPastedShare());
        attemptRecoveryButton.setOnClickListener(v -> attemptRecovery());
    }

    @Override
    public boolean onSupportNavigateUp() {
        onBackPressed();
        return true;
    }

    private void selectBackupFile() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, REQUEST_SELECT_BACKUP_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (opHelper != null) {
            opHelper.handleActivityResult(requestCode, resultCode, data);
        }
        if (requestCode == REQUEST_SELECT_BACKUP_FILE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                readBackupFile(uri);
            }
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    private void readBackupFile(Uri uri) {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int read;
            while (in != null && (read = in.read(chunk)) != -1) {
                buffer.write(chunk, 0, read);
            }
            backupBytes = buffer.toByteArray();
            backupFileStatus.setText(R.string.social_recovery_backup_file_selected);
        } catch (IOException e) {
            Toast.makeText(this, R.string.social_recovery_error_no_backup_file, Toast.LENGTH_SHORT).show();
        }
        updateRecoveryButtonState();
    }

    private void addPastedShare() {
        String text = pasteShareInput.getText().toString();
        TrusteeShareBundle bundle;
        try {
            bundle = TrusteeShareBundleTextCodec.decode(text);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, R.string.social_recovery_error_invalid_share, Toast.LENGTH_SHORT).show();
            return;
        }
        if (masterKeyId == -1) {
            masterKeyId = bundle.getMasterKeyId();
        } else if (bundle.getMasterKeyId() != masterKeyId) {
            Toast.makeText(this, R.string.social_recovery_error_invalid_share, Toast.LENGTH_SHORT).show();
            return;
        }

        addedShares.add(bundle);
        pasteShareInput.setText("");

        View row = LayoutInflater.from(this)
                .inflate(R.layout.item_trustee_share_result_row, addedSharesContainer, false);
        TextView label = row.findViewById(R.id.trustee_result_label);
        label.setText(getString(R.string.social_recovery_trustee_result_label, bundle.getTrusteeLabel(), bundle.getWeight()));
        Button removeButton = row.findViewById(R.id.trustee_result_share_button);
        removeButton.setText(R.string.social_recovery_remove_trustee);
        removeButton.setOnClickListener(v -> {
            addedShares.remove(bundle);
            addedSharesContainer.removeView(row);
            updateRecoveryButtonState();
        });
        addedSharesContainer.addView(row);

        updateRecoveryButtonState();
    }

    private void updateRecoveryButtonState() {
        if (addedShares.isEmpty()) {
            weightProgressText.setText(R.string.social_recovery_no_shares_added);
        } else {
            int threshold = addedShares.get(0).getThresholdWeight();
            Set<Integer> distinctIndices = new LinkedHashSet<>();
            for (TrusteeShareBundle bundle : addedShares) {
                distinctIndices.addAll(bundle.getShareIndices());
            }
            weightProgressText.setText(getString(
                    R.string.social_recovery_weight_progress, distinctIndices.size(), threshold));
        }
        attemptRecoveryButton.setEnabled(backupBytes != null && !addedShares.isEmpty());
    }

    private void attemptRecovery() {
        if (backupBytes == null || addedShares.isEmpty()) {
            return;
        }

        String ceremonyId = addedShares.get(0).getCeremonyId();
        SocialRecoveryReconstructParcel input = SocialRecoveryReconstructParcel.create(
                masterKeyId, ceremonyId, new ArrayList<>(addedShares), backupBytes);

        CryptoOperationHelper.Callback<SocialRecoveryReconstructParcel, SocialRecoveryReconstructResult> callback =
                new CryptoOperationHelper.Callback<SocialRecoveryReconstructParcel, SocialRecoveryReconstructResult>() {
            @Override
            public SocialRecoveryReconstructParcel createOperationInput() {
                return input;
            }

            @Override
            public void onCryptoOperationSuccess(SocialRecoveryReconstructResult result) {
                Toast.makeText(SocialRecoveryRestoreActivity.this,
                        R.string.social_recovery_recovery_success, Toast.LENGTH_LONG).show();
                if (result.recoveredMasterKeyId != null) {
                    startActivity(ViewKeyActivity.getViewKeyActivityIntent(
                            SocialRecoveryRestoreActivity.this, result.recoveredMasterKeyId));
                }
                finish();
            }

            @Override
            public void onCryptoOperationCancelled() {
            }

            @Override
            public void onCryptoOperationError(SocialRecoveryReconstructResult result) {
                result.createNotify(SocialRecoveryRestoreActivity.this).show();
            }

            @Override
            public boolean onCryptoSetProgress(String msg, int progress, int max) {
                return false;
            }
        };

        opHelper = new CryptoOperationHelper<>(2, this, callback, R.string.social_recovery_recovery_in_progress);
        opHelper.cryptoOperation(CryptoInputParcel.createCryptoInputParcel());
    }
}
