package org.cryptimeleon.craco.prf.zn;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.prf.PrfKey;
import org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction;
import org.cryptimeleon.math.hash.HashFunction;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Get pseudorandom Zn Elements by a hash-then-prf construction.
 *
 * The main concept is to use an oversubscribed PRF in the sense that the output bitsize is hundrets of bits larger
 * than Zn Elements. We divide the output space into an accepting interval [0, k*p[ and a rejecting interval. If the
 * output of hash-then-prf is in the accepting interval, we make the remainder mod p the output Zn element, since it
 * is uniformly at random from [0, k*p[ and hence the remainder u.a.r. from Zn. We reject all results from the rejecting
 * interval. We choose the rejecting intervals size to be negligible compared to the accepting to avoid retrying
 * by using {@link LongAesPseudoRandomFunction}.
 */
public class HashThenPrfToZn {
    private final LongAesPseudoRandomFunction longAesPseudoRandomFunction;
    private final HashFunction hashFunction;
    private final Zn zn;
    private final BigInteger p;
    private final BigInteger maxQuotient; // k from the description
    final int OVERSUBSCRIPTION = 2; // Make accepting interval larger than rejecting interval (+rounding overhead)

    /**
     * @param aesKeyLength  bit length of AES
     * @param zn target ring
     * @param hashFunction hash function to use, output size should be larger than AES input size
     */
    public HashThenPrfToZn(int aesKeyLength, Zn zn, HashFunction hashFunction) {
        if (hashFunction.getOutputLength() * 8 < aesKeyLength) {
            throw new IllegalArgumentException("Hash function output should be larger or equal to AES input size.");
        }

        this.hashFunction = hashFunction;
        this.zn = zn;
        this.p = zn.getCharacteristic();
        this.longAesPseudoRandomFunction = new LongAesPseudoRandomFunction(
                new AesPseudorandomFunction(aesKeyLength),
                (p.bitLength() + aesKeyLength + OVERSUBSCRIPTION + 1) / aesKeyLength  // Compute number of AES instances required to get desired output bit length
        );

        // Compute quotient of prf output all 1s divided by p
        // We can use all remainders with quotients strictly smaller than that quotient to draw uniformly at random from Zp
        byte[] bytes = new byte[longAesPseudoRandomFunction.getKeyLengthBytes()];
        Arrays.fill(bytes, (byte) 255);

        BigInteger[] dar = new BigInteger(1, bytes).divideAndRemainder(p);
        this.maxQuotient = dar[0];
    }

    /**
     * Generates a PRF key that can be used to hash-then-prf to Zn
     * @return a PRF key
     */
    public PrfKey generateKey() {
        return longAesPseudoRandomFunction.generateKey();
    }

    /**
     * Hash-then-PRF to Zn.
     *
     * @param prfKey the PRF key
     * @param hashInput input to hash
     * @return a pseudorandom Zn element
     */
    public Zn.ZnElement hashThenPrfToZn(PrfKey prfKey, UniqueByteRepresentable hashInput) {
        // Compute hash value
        byte[] hashOutput = hashFunction.hash(hashInput);

        // Truncate hash
        byte[] prfInput = new byte[longAesPseudoRandomFunction.getPreimageLengthBytes()];
        System.arraycopy(hashOutput, 0, prfInput, 0, longAesPseudoRandomFunction.getPreimageLengthBytes());

        // Compute prf(hash)
        ByteArrayImplementation prfOutput = longAesPseudoRandomFunction.evaluate(prfKey, new ByteArrayImplementation(prfInput));

        //Compute quotient and remainder of the prf output interpreted as a positive integer. Return remainder as
        // ZnElement if quotient is smaller than largest quotient to ensurer elements are drawn uniformly at random
        // from Zn
        BigInteger[] quotientAndRemainder = new BigInteger(1, prfOutput.getData()).divideAndRemainder(p);

        if (quotientAndRemainder[0].compareTo(maxQuotient) < 0) {
            throw new RuntimeException("PRF output is in the reject interval!");
        }

        return zn.valueOf(quotientAndRemainder[1]);
    }

}
