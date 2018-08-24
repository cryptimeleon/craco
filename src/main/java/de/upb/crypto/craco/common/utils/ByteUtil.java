package de.upb.crypto.craco.common.utils;


/**
 * Various byte[] helper methods.
 *
 * @author Marius Dransfeld
 */
public final class ByteUtil {
    /**
     * Hidden constructor.
     */
    private ByteUtil() {

    }

    /**
     * Computes bytewise XOR of two arrays.
     *
     * @param a first byte array
     * @param b second byte array
     * @return a XOR b
     */
    public static byte[] xor(final byte[] a, final byte[] b) {
        assert (a.length == b.length);

        byte[] result = new byte[a.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
