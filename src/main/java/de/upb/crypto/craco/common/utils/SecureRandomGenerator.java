package de.upb.crypto.craco.common.utils;

import de.upb.crypto.math.random.interfaces.RandomGenerator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;


/**
 * {@code RandomGenerator} which uses {@link SecureRandom}.
 *
 * @author Marius Dransfeld
 */
public final class SecureRandomGenerator implements RandomGenerator {
    private Random rng = new SecureRandom();

    @Override
    public BigInteger next(int length) {
        byte[] bytes;

        if (length % 8 == 0) {
            bytes = new byte[length / 8];
        } else {
            bytes = new byte[length / 8 + 1];
        }

        rng.nextBytes(bytes);

        BigInteger result = new BigInteger(bytes);
        result = result.abs();
        return result;
    }

    @Override
    public boolean nextBit() {
        return rng.nextBoolean();
    }

    @Override
    public void setSeed(BigInteger seed) {
        rng.setSeed(seed.longValue());
    }

    @Override
    public byte[] getRandomByteArray(int l) {
        byte[] result = new byte[l];
        rng.nextBytes(result);
        return result;
    }

}
