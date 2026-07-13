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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import android.util.Base64;

import org.sufficientlysecure.keychain.socialrecovery.TrusteeShareBundle;

/**
 * A trustee's share bundle, as text for out-of-band distribution (copy/paste, share sheet).
 * Length-prefixed binary fields Base64-encoded as one line, rather than a delimiter-separated
 * format -- avoids any escaping question for trustee labels containing arbitrary characters.
 * Not a security boundary: {@link TrusteeShareBundle#getShareChecksum} is what a recipient
 * checks their share against, this codec's own correctness is verified by round-trip tests.
 */
public class TrusteeShareBundleTextCodec {

    private static final String PREFIX = "SRSHARE1:";

    private TrusteeShareBundleTextCodec() {
    }

    public static String encode(TrusteeShareBundle bundle) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);

            out.writeLong(bundle.getMasterKeyId());
            writeString(out, bundle.getCeremonyId());
            writeString(out, bundle.getTrusteeLabel());
            out.writeInt(bundle.getThresholdWeight());
            out.writeInt(bundle.getTotalWeight());

            List<Integer> indices = bundle.getShareIndices();
            List<byte[]> shareBytes = bundle.getShareBytes();
            out.writeInt(indices.size());
            for (int i = 0; i < indices.size(); i++) {
                out.writeInt(indices.get(i));
                out.writeInt(shareBytes.get(i).length);
                out.write(shareBytes.get(i));
            }

            return PREFIX + Base64.encodeToString(bytes.toByteArray(), Base64.NO_WRAP);
        } catch (IOException e) {
            throw new IllegalStateException("encoding to an in-memory stream must not fail", e);
        }
    }

    public static TrusteeShareBundle decode(String text) throws IllegalArgumentException {
        String trimmed = text == null ? "" : text.trim();
        if (!trimmed.startsWith(PREFIX)) {
            throw new IllegalArgumentException("not a recognized share (missing " + PREFIX + " prefix)");
        }

        try {
            byte[] bytes = Base64.decode(trimmed.substring(PREFIX.length()), Base64.NO_WRAP);
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));

            long masterKeyId = in.readLong();
            String ceremonyId = readString(in);
            String trusteeLabel = readString(in);
            int thresholdWeight = in.readInt();
            int totalWeight = in.readInt();

            int shareCount = in.readInt();
            List<Integer> indices = new ArrayList<>(shareCount);
            List<byte[]> shareBytes = new ArrayList<>(shareCount);
            for (int i = 0; i < shareCount; i++) {
                indices.add(in.readInt());
                int length = in.readInt();
                byte[] share = new byte[length];
                in.readFully(share);
                shareBytes.add(share);
            }

            return TrusteeShareBundle.create(
                    trusteeLabel, indices, shareBytes, masterKeyId, ceremonyId, thresholdWeight, totalWeight);
        } catch (IOException | RuntimeException e) {
            throw new IllegalArgumentException("could not parse share text", e);
        }
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(utf8.length);
        out.write(utf8);
    }

    private static String readString(DataInputStream in) throws IOException {
        int length = in.readInt();
        byte[] utf8 = new byte[length];
        in.readFully(utf8);
        return new String(utf8, StandardCharsets.UTF_8);
    }
}
