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
import androidx.core.content.ContextCompat;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.ui.util.DecayingSignal.Level;


/**
 * Shows whether a key's passphrase is currently cached, and -- for TTL-mode caching -- a
 * bucketed "Fresh / Expiring soon / Expiring imminently" indicator rather than a raw countdown,
 * using {@link org.sufficientlysecure.keychain.ui.util.DecayingSignal} so the displayed bucket
 * doesn't need to update every second to stay meaningful. Hidden entirely if nothing is cached.
 */
public class PassphraseCacheStatusView extends FrameLayout {
    private final TextView vTitle;
    private final TextView vSubtitle;
    private final ImageView vIcon;

    public PassphraseCacheStatusView(Context context, AttributeSet attrs) {
        super(context, attrs);

        View view = LayoutInflater.from(context).inflate(R.layout.key_passphrase_cache_status_layout, this, true);

        vTitle = view.findViewById(R.id.passphrase_cache_status_title);
        vSubtitle = view.findViewById(R.id.passphrase_cache_status_subtitle);
        vIcon = view.findViewById(R.id.passphrase_cache_status_icon);
    }

    public void setNotCached() {
        setVisibility(View.GONE);
    }

    public void setCachedWithoutTimeout() {
        vTitle.setText(R.string.passphrase_cache_status_title);
        vSubtitle.setText(R.string.passphrase_cache_status_no_timeout);
        vIcon.setColorFilter(ContextCompat.getColor(getContext(), R.color.android_green_light));
        setVisibility(View.VISIBLE);
    }

    public void setCachedWithTtlLevel(Level level) {
        vTitle.setText(R.string.passphrase_cache_status_title);
        switch (level) {
            case HIGH:
                vSubtitle.setText(R.string.passphrase_cache_status_fresh);
                vIcon.setColorFilter(ContextCompat.getColor(getContext(), R.color.android_green_light));
                break;
            case MEDIUM:
                vSubtitle.setText(R.string.passphrase_cache_status_expiring_soon);
                vIcon.setColorFilter(ContextCompat.getColor(getContext(), R.color.android_orange_light));
                break;
            case LOW:
            default:
                vSubtitle.setText(R.string.passphrase_cache_status_expiring_now);
                vIcon.setColorFilter(ContextCompat.getColor(getContext(), R.color.android_red_light));
                break;
        }
        setVisibility(View.VISIBLE);
    }
}
