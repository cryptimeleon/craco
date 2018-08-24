package de.upb.crypto.craco.kdf.uextr;

import java.math.BigInteger;

public class BigIntegerUtil {

    public static BigInteger getUnsingendBigInteger(byte[] bytes) {
        BigInteger result = BigInteger.valueOf(0);

        for (int i = 0; i < bytes.length; i++) {
            result = result.add(BigInteger.valueOf(bytes[i] << 8 * (bytes.length - i - 1)));
        }
        return result;
    }
}
