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

package org.sufficientlysecure.keychain.ui.keyview.view;


import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;

import org.sufficientlysecure.keychain.R;


/**
 * Shows the app version and entropy source a key was generated with, if recorded (keys created
 * before this feature shipped, or imported keys, have no such metadata and this stays hidden).
 */
public class ProvenanceStatusView extends FrameLayout {
    private final TextView vSubtitle;

    public ProvenanceStatusView(Context context, AttributeSet attrs) {
        super(context, attrs);

        View view = LayoutInflater.from(context).inflate(R.layout.key_provenance_status_layout, this, true);

        vSubtitle = view.findViewById(R.id.provenance_status_subtitle);
    }

    public void setUnknown() {
        setVisibility(View.GONE);
    }

    public void setProvenance(String appVersion, String entropySource) {
        if (appVersion == null || entropySource == null) {
            setUnknown();
            return;
        }
        vSubtitle.setText(getResources().getString(R.string.provenance_status_subtitle, appVersion, entropySource));
        setVisibility(View.VISIBLE);
    }
}
