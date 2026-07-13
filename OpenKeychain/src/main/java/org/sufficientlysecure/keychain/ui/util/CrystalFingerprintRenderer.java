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

package org.sufficientlysecure.keychain.ui.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;

/**
 * Renders a key fingerprint as a small left-right-symmetric "crystal" -- a companion to the QR
 * code that's recognizable at a glance rather than scannable. Same fingerprint bytes always
 * render the same image; this is a perceptual hash for human comparison, not a security
 * boundary, so {@link Random} (not a CSPRNG) is deliberately sufficient here.
 */
public class CrystalFingerprintRenderer {

    // Number of vertices generated for one (right) half of the shape, before mirroring. Total
    // polygon vertex count is 2 * halfVertexCount - 2 (the top and bottom vertices lie on the
    // axis of symmetry and aren't duplicated), so this range yields 6-12 total vertices.
    private static final int MIN_HALF_VERTICES = 4;
    private static final int MAX_HALF_VERTICES = 7;

    private static final float MIN_RADIUS_FRACTION = 0.45f;
    private static final float MAX_RADIUS_FRACTION = 0.92f;

    private static final int BASE_FILL_COLOR = Color.parseColor("#2D1B69"); // pqc_violet_primary
    private static final int[] FACET_ACCENT_COLORS = {
            Color.parseColor("#0097A7"), // pqc_cyan_accent_on_light
            Color.parseColor("#FF2ED1"), // pqc_magenta_signature
    };

    private CrystalFingerprintRenderer() {
    }

    public static Bitmap render(byte[] fingerprintBytes, int size) {
        if (fingerprintBytes == null || fingerprintBytes.length == 0) {
            throw new IllegalArgumentException("fingerprintBytes must not be empty");
        }
        if (size <= 0) {
            throw new IllegalArgumentException("size must be positive");
        }

        Random random = new Random(seedFrom(fingerprintBytes));
        List<float[]> polygonPoints = buildSymmetricPolygon(random, size);

        Bitmap bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        canvas.drawColor(Color.WHITE);

        Path outline = pathFrom(polygonPoints);

        Paint basePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        basePaint.setStyle(Paint.Style.FILL);
        basePaint.setColor(BASE_FILL_COLOR);
        canvas.drawPath(outline, basePaint);

        drawFacets(canvas, polygonPoints, size / 2f, size / 2f, random);

        Paint outlinePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        outlinePaint.setStyle(Paint.Style.STROKE);
        outlinePaint.setStrokeWidth(size * 0.015f);
        outlinePaint.setColor(FACET_ACCENT_COLORS[0]);
        canvas.drawPath(outline, outlinePaint);

        return bitmap;
    }

    private static List<float[]> buildSymmetricPolygon(Random random, int size) {
        int halfVertexCount = MIN_HALF_VERTICES
                + random.nextInt(MAX_HALF_VERTICES - MIN_HALF_VERTICES + 1);

        float centerX = size / 2f;
        float centerY = size / 2f;
        float maxRadius = (size / 2f) * MAX_RADIUS_FRACTION;

        // Sweep top (angle 0) to bottom (angle 180) down the right side of the shape.
        List<float[]> rightHalf = new ArrayList<>(halfVertexCount);
        for (int i = 0; i < halfVertexCount; i++) {
            double angleRad = Math.toRadians(180.0 * i / (halfVertexCount - 1));
            float radiusFraction = MIN_RADIUS_FRACTION
                    + random.nextFloat() * (1f - MIN_RADIUS_FRACTION);
            float radius = maxRadius * radiusFraction;
            float x = centerX + (float) (radius * Math.sin(angleRad));
            float y = centerY - (float) (radius * Math.cos(angleRad));
            rightHalf.add(new float[] { x, y });
        }

        List<float[]> polygonPoints = new ArrayList<>(halfVertexCount * 2);
        polygonPoints.addAll(rightHalf);
        // Mirror the interior right-side vertices (excluding top/bottom, which sit on the axis
        // of symmetry) back up the left side, continuing the same clockwise winding.
        for (int i = halfVertexCount - 2; i >= 1; i--) {
            float[] mirrored = rightHalf.get(i);
            polygonPoints.add(new float[] { 2 * centerX - mirrored[0], mirrored[1] });
        }
        return polygonPoints;
    }

    private static Path pathFrom(List<float[]> points) {
        Path path = new Path();
        float[] first = points.get(0);
        path.moveTo(first[0], first[1]);
        for (int i = 1; i < points.size(); i++) {
            float[] point = points.get(i);
            path.lineTo(point[0], point[1]);
        }
        path.close();
        return path;
    }

    private static void drawFacets(Canvas canvas, List<float[]> points, float centerX, float centerY,
            Random random) {
        Paint facetPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        facetPaint.setStyle(Paint.Style.FILL);

        int pointCount = points.size();
        for (int i = 0; i < pointCount; i++) {
            float[] a = points.get(i);
            float[] b = points.get((i + 1) % pointCount);

            Path facet = new Path();
            facet.moveTo(centerX, centerY);
            facet.lineTo(a[0], a[1]);
            facet.lineTo(b[0], b[1]);
            facet.close();

            facetPaint.setColor(FACET_ACCENT_COLORS[i % FACET_ACCENT_COLORS.length]);
            facetPaint.setAlpha(40 + random.nextInt(70));
            canvas.drawPath(facet, facetPaint);
        }
    }

    // Package-visible (rather than private) specifically so tests can verify the
    // determinism/uniqueness contract directly, without depending on Robolectric's
    // Canvas/Path rasterization fidelity for pixel-level comparison.
    static long seedFrom(byte[] fingerprintBytes) {
        long seed = 1125899906842597L;
        for (byte b : fingerprintBytes) {
            seed = seed * 31 + b;
        }
        return seed;
    }
}
