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

import java.util.ArrayList;
import java.util.List;

import android.content.Intent;
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
import org.sufficientlysecure.keychain.operations.results.SocialRecoverySplitResult;
import org.sufficientlysecure.keychain.service.SocialRecoverySplitParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;
import org.sufficientlysecure.keychain.socialrecovery.TrusteeWeight;
import org.sufficientlysecure.keychain.ui.base.CryptoOperationHelper;
import org.sufficientlysecure.keychain.util.ProgressScaler;

/**
 * Minimal, functional setup screen for B7 -- a trustee list (label + weight), a threshold, and
 * a "Create Recovery Shares" button. Not a polished multi-step wizard; per the design, the
 * split/reconstruct core's correctness is the deliverable, this is the entry point to it.
 */
public class SocialRecoverySetupActivity extends AppCompatActivity {
    public static final String EXTRA_MASTER_KEY_ID = "master_key_id";

    private long masterKeyId;

    private LinearLayout trusteeRowsContainer;
    private EditText thresholdWeightInput;
    private LinearLayout resultsContainer;
    private LinearLayout trusteeResultsContainer;
    private Button createSharesButton;
    private Button shareBackupFileButton;

    private List<TrusteeShareBundle> lastSplitBundles;
    private android.net.Uri lastBackupUri;

    private CryptoOperationHelper<SocialRecoverySplitParcel, SocialRecoverySplitResult> opHelper;

    public static Intent createIntent(android.content.Context context, long masterKeyId) {
        Intent intent = new Intent(context, SocialRecoverySetupActivity.class);
        intent.putExtra(EXTRA_MASTER_KEY_ID, masterKeyId);
        return intent;
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_social_recovery_setup);

        masterKeyId = getIntent().getLongExtra(EXTRA_MASTER_KEY_ID, -1);
        if (masterKeyId == -1) {
            throw new IllegalArgumentException("Missing required extra master_key_id");
        }

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.social_recovery_setup_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        trusteeRowsContainer = findViewById(R.id.trustee_rows_container);
        thresholdWeightInput = findViewById(R.id.threshold_weight_input);
        resultsContainer = findViewById(R.id.results_container);
        trusteeResultsContainer = findViewById(R.id.trustee_results_container);
        createSharesButton = findViewById(R.id.create_shares_button);
        shareBackupFileButton = findViewById(R.id.share_backup_file_button);

        findViewById(R.id.add_trustee_button).setOnClickListener(v -> addTrusteeRow());
        addTrusteeRow();
        addTrusteeRow();

        createSharesButton.setOnClickListener(v -> onCreateSharesClicked());
        shareBackupFileButton.setOnClickListener(v -> shareBackupFile());
    }

    @Override
    public boolean onSupportNavigateUp() {
        onBackPressed();
        return true;
    }

    private void addTrusteeRow() {
        View row = LayoutInflater.from(this).inflate(R.layout.item_trustee_weight_row, trusteeRowsContainer, false);
        row.findViewById(R.id.trustee_remove_button).setOnClickListener(v -> trusteeRowsContainer.removeView(row));
        trusteeRowsContainer.addView(row);
    }

    private void onCreateSharesClicked() {
        List<TrusteeWeight> trustees = readTrusteesFromRows();
        if (trustees == null) {
            return;
        }

        Integer thresholdWeight = parsePositiveInt(thresholdWeightInput.getText().toString());
        if (thresholdWeight == null) {
            Toast.makeText(this, R.string.social_recovery_error_invalid_threshold, Toast.LENGTH_SHORT).show();
            return;
        }

        SocialRecoverySplitParcel input = SocialRecoverySplitParcel.create(masterKeyId, trustees, thresholdWeight);

        CryptoOperationHelper.Callback<SocialRecoverySplitParcel, SocialRecoverySplitResult> callback =
                new CryptoOperationHelper.Callback<SocialRecoverySplitParcel, SocialRecoverySplitResult>() {
            @Override
            public SocialRecoverySplitParcel createOperationInput() {
                return input;
            }

            @Override
            public void onCryptoOperationSuccess(SocialRecoverySplitResult result) {
                showResults(result);
            }

            @Override
            public void onCryptoOperationCancelled() {
            }

            @Override
            public void onCryptoOperationError(SocialRecoverySplitResult result) {
                result.createNotify(SocialRecoverySetupActivity.this).show();
            }

            @Override
            public boolean onCryptoSetProgress(String msg, int progress, int max) {
                return false;
            }
        };

        opHelper = new CryptoOperationHelper<>(1, this, callback, R.string.social_recovery_split_in_progress);
        opHelper.cryptoOperation(CryptoInputParcel.createCryptoInputParcel());
    }

    @Nullable
    private List<TrusteeWeight> readTrusteesFromRows() {
        List<TrusteeWeight> trustees = new ArrayList<>();
        for (int i = 0; i < trusteeRowsContainer.getChildCount(); i++) {
            View row = trusteeRowsContainer.getChildAt(i);
            EditText labelInput = row.findViewById(R.id.trustee_label_input);
            EditText weightInput = row.findViewById(R.id.trustee_weight_input);

            String label = labelInput.getText().toString().trim();
            if (label.isEmpty()) {
                continue;
            }
            Integer weight = parsePositiveInt(weightInput.getText().toString());
            if (weight == null) {
                Toast.makeText(this, R.string.social_recovery_error_invalid_weight, Toast.LENGTH_SHORT).show();
                return null;
            }
            trustees.add(TrusteeWeight.create(label, weight));
        }
        if (trustees.isEmpty()) {
            Toast.makeText(this, R.string.social_recovery_error_no_trustees, Toast.LENGTH_SHORT).show();
            return null;
        }
        return trustees;
    }

    @Nullable
    private static Integer parsePositiveInt(String text) {
        try {
            int value = Integer.parseInt(text.trim());
            return value > 0 ? value : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private void showResults(SocialRecoverySplitResult result) {
        lastSplitBundles = result.trusteeBundles;
        lastBackupUri = result.encryptedBackupUri;

        trusteeResultsContainer.removeAllViews();
        for (TrusteeShareBundle bundle : lastSplitBundles) {
            View row = LayoutInflater.from(this)
                    .inflate(R.layout.item_trustee_share_result_row, trusteeResultsContainer, false);
            TextView label = row.findViewById(R.id.trustee_result_label);
            label.setText(getString(R.string.social_recovery_trustee_result_label,
                    bundle.getTrusteeLabel(), bundle.getWeight()));
            row.findViewById(R.id.trustee_result_share_button).setOnClickListener(v -> shareTrusteeBundle(bundle));
            trusteeResultsContainer.addView(row);
        }

        resultsContainer.setVisibility(View.VISIBLE);
        createSharesButton.setEnabled(false);
    }

    private void shareTrusteeBundle(TrusteeShareBundle bundle) {
        String encoded = TrusteeShareBundleTextCodec.encode(bundle);
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TEXT, encoded);
        startActivity(Intent.createChooser(intent,
                getString(R.string.social_recovery_trustee_result_label, bundle.getTrusteeLabel(), bundle.getWeight())));
    }

    private void shareBackupFile() {
        if (lastBackupUri == null) {
            return;
        }
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType(org.sufficientlysecure.keychain.Constants.MIME_TYPE_ENCRYPTED_ALTERNATE);
        intent.putExtra(Intent.EXTRA_STREAM, lastBackupUri);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivity(Intent.createChooser(intent, getString(R.string.social_recovery_share_backup_file)));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (opHelper != null) {
            opHelper.handleActivityResult(requestCode, resultCode, data);
        }
        super.onActivityResult(requestCode, resultCode, data);
    }
}
