package org.sufficientlysecure.keychain.util;


import java.io.InputStream;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;


@RunWith(KeychainTestRunner.class)
public class KeyFormattingUtilsTest {

    static final byte[] fp = new byte[] {
        (byte) 0xD4, (byte) 0xAB, (byte) 0x19, (byte) 0x29, (byte) 0x64,
        (byte) 0xF7, (byte) 0x6A, (byte) 0x7F, (byte) 0x8F, (byte) 0x8A,
        (byte) 0x9B, (byte) 0x35, (byte) 0x7B, (byte) 0xD1, (byte) 0x83,
        (byte) 0x20, (byte) 0xDE, (byte) 0xAD, (byte) 0xFA, (byte) 0x11
    };
    static final long keyId = 0x7bd18320deadfa11L;

    /**
     * The real draft-ietf-openpgp-pqc-17 v6 ML-DSA-87+Ed448 sample public key (same resource
     * used by {@code CompositeMlDsa87Ed448SignVerifyTest}'s known-answer test), used here as a
     * real, non-fabricated 32-byte v6 fingerprint rather than a hand-rolled test vector.
     */
    static final String V6_TEST_KEY_RESOURCE = "/test-keys/v6-mldsa-87-sample-pk.asc";

    /**
     * The v6 fingerprint of the above key, as verified byte-for-byte against the draft text in
     * {@code CompositeMlDsa87Ed448SignVerifyTest.testKnownAnswerAgainstOfficialDraftTestVector}.
     */
    static final String V6_FINGERPRINT_HEX =
            "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20";

    // Per RFC 9580 5.5.4.3, the v6 Key ID is the high-order (first) 64 bits of the fingerprint.
    static final long V6_KEY_ID = 0x0d7a8be1410cd68eL;

    @Test
    public void testStuff() {
        Assert.assertEquals(KeyFormattingUtils.convertFingerprintToKeyId(fp), keyId);

        Assert.assertEquals(
            "d4ab192964f76a7f8f8a9b357bd18320deadfa11",
            KeyFormattingUtils.convertFingerprintToHex(fp)
        );

        Assert.assertEquals(
            "0x7bd18320deadfa11",
            KeyFormattingUtils.convertKeyIdToHex(keyId)
        );

        Assert.assertEquals(
                "0xdeadfa11",
                KeyFormattingUtils.convertKeyIdToHexShort(keyId)
        );

    }

    /**
     * convertFingerprintToHex must accept a real 32-byte v6 fingerprint (rejected before this
     * fix, which only accepted 16- or 20-byte input) and produce the correct lowercase hex.
     */
    @Test
    public void testConvertFingerprintToHex_acceptsRealV6Fingerprint() throws Exception {
        byte[] v6Fingerprint = loadV6TestKeyFingerprint();

        assertEquals(32, v6Fingerprint.length);
        assertEquals(V6_FINGERPRINT_HEX, KeyFormattingUtils.convertFingerprintToHex(v6Fingerprint));
    }

    /**
     * getKeyIdFromFingerprint must extract the correct Key ID for a v6 fingerprint: per RFC 9580
     * 5.5.4.3, the high-order (first) 64 bits -- the opposite end of the buffer from v4's
     * low-order (last) 64 bits.
     */
    @Test
    public void testGetKeyIdFromFingerprint_v6UsesHighOrderBytes() throws Exception {
        byte[] v6Fingerprint = loadV6TestKeyFingerprint();

        long v6KeyId = KeyFormattingUtils.getKeyIdFromFingerprint(v6Fingerprint);
        assertEquals(V6_KEY_ID, v6KeyId);

        // sanity: the last-8-bytes (v4 convention) would NOT match, proving this isn't
        // accidentally reading the wrong end of the buffer
        Assert.assertNotEquals(v6KeyId,
                java.nio.ByteBuffer.wrap(v6Fingerprint, 24, 8).getLong());
    }

    /** convertFingerprintToKeyId must agree with getKeyIdFromFingerprint for v6 fingerprints too. */
    @Test
    public void testConvertFingerprintToKeyId_agreesForV6() throws Exception {
        byte[] v6Fingerprint = loadV6TestKeyFingerprint();

        assertEquals(
                KeyFormattingUtils.getKeyIdFromFingerprint(v6Fingerprint),
                KeyFormattingUtils.convertFingerprintToKeyId(v6Fingerprint));
    }

    /** convertFingerprintHexFingerprint must accept a 64-hex-char (32-byte) v6 fingerprint. */
    @Test
    public void testConvertFingerprintHexFingerprint_acceptsV6Length() {
        byte[] decoded = KeyFormattingUtils.convertFingerprintHexFingerprint(V6_FINGERPRINT_HEX);
        assertEquals(32, decoded.length);
        assertEquals(V6_FINGERPRINT_HEX, Hex.toHexString(decoded));
    }

    /** A v4-length fingerprint hex string must still round-trip as before (no regression). */
    @Test
    public void testConvertFingerprintHexFingerprint_stillAcceptsV4Length() {
        String v4Hex = "d4ab192964f76a7f8f8a9b357bd18320deadfa11";
        byte[] decoded = KeyFormattingUtils.convertFingerprintHexFingerprint(v4Hex);
        assertEquals(20, decoded.length);
    }

    /** Lengths that are neither v4 nor v6 must still be rejected. */
    @Test
    public void testConvertFingerprintHexFingerprint_rejectsBadLength() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyFormattingUtils.convertFingerprintHexFingerprint("abcd"));
    }

    /**
     * formatFingerprint must place its line break at the midpoint of the *groups*, not at a
     * hardcoded character offset -- for a v6 (64-hex-char) fingerprint that offset would fall
     * mid-group under the old fixed chars[24] logic.
     */
    @Test
    public void testFormatFingerprint_v6LineBreakAtGroupMidpoint() {
        String formatted = KeyFormattingUtils.formatFingerprint(V6_FINGERPRINT_HEX);
        String[] lines = formatted.split("\n");

        assertEquals("must produce exactly two lines", 2, lines.length);
        assertEquals("first line must be exactly 8 groups of 4 (39 chars incl. spaces)",
                "0d7a 8be1 410c d68e ed48 45ab 487b 4b4c", lines[0]);
        assertEquals("second line must be the remaining 8 groups",
                "faec d8eb ad1a 1166 a842 3049 9200 ee20", lines[1]);
    }

    /** formatFingerprint must still produce the historical 5+5 split for a v4 fingerprint. */
    @Test
    public void testFormatFingerprint_v4StillSplits5And5() {
        String v4Hex = "d4ab192964f76a7f8f8a9b357bd18320deadfa11";
        String formatted = KeyFormattingUtils.formatFingerprint(v4Hex);
        String[] lines = formatted.split("\n");

        assertEquals(2, lines.length);
        assertEquals("d4ab 1929 64f7 6a7f 8f8a", lines[0]);
        assertEquals("9b35 7bd1 8320 dead fa11", lines[1]);
    }

    private static byte[] loadV6TestKeyFingerprint() throws Exception {
        try (InputStream in = KeyFormattingUtilsTest.class.getResourceAsStream(V6_TEST_KEY_RESOURCE)) {
            assertNotNull("test resource must be present: " + V6_TEST_KEY_RESOURCE, in);
            try (InputStream decoderStream = PGPUtil.getDecoderStream(in)) {
                PGPObjectFactory factory =
                        new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
                PGPPublicKeyRing ring = (PGPPublicKeyRing) factory.nextObject();
                PGPPublicKey masterKey = ring.getPublicKey();
                assertEquals(6, masterKey.getVersion());
                return masterKey.getFingerprint();
            }
        }
    }

}
