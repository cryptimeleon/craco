package org.cryptimeleon.craco.prf.zn;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.prf.PrfKey;
import org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction;
import org.cryptimeleon.math.hash.HashFunction;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.impl.ByteArrayAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;
import java.util.Vector;

/**
 * Get pseudorandom Zn Elements by a hash-then-prf construction.
 * <p>
 * We use a PRF that outputs bitstrings and map these to Zp as follows:
 * We divide the output interval of size 2^n (with elements in [0,2^n-1]) into a 'good' and a 'bad' interval, where the
 * good interval is [0,x*p[ with x*p{@literal <}2^n chosen to be maximal and the bad interval [x*p,2^n-1].
 * Since x is maximal, the bad interval has size at most p-1.
 * <p>
 * To get a ZnElement, we hash, use the PRF and get some output value o.
 * If o is in the good interval, we output o mod p
 * as our ZnElement. This is random for random bit strings, since the good interval's size is a multiple of p.
 * If o is in the bad interval, we reject and throw an exception. We don't want this to happen, hence we increase the
 * good interval by using a longer PRF, this can be influenced by the so called 'oversubscription'. Since the bad
 * interval's size is bound by p, increasing the total interval reduces the probability of landing in the bad interval.
 * More precisely, the reject rate is bound by (1/2)^oversubscription.
 */
public class HashThenPrfToZn implements StandaloneRepresentable {
    @Represented
    private LongAesPseudoRandomFunction longAesPseudoRandomFunction;
    @Represented
    private HashFunction hashFunction;
    @Represented
    private Zn zn;

    // Redundant parameter that we do not want to compute every time we use this
    private BigInteger maxQuotient; // k from the description

    /**
     * Instantiate HashThenPrfToZn
     *
     * @param aesKeyLength     bit length of AES
     * @param zn               target ring
     * @param hashFunction     hash function to use, output size should be larger than AES input size
     * @param oversubscription parameter that binds the probability of failing by (1/2)^oversubscription. Probability can be lower due to rounding
     */
    public HashThenPrfToZn(int aesKeyLength, Zn zn, HashFunction hashFunction, int oversubscription) {
        if (hashFunction.getOutputLength() * 8 < aesKeyLength) {
            throw new IllegalArgumentException("Hash function output should be larger or equal to AES input size.");
        }

        this.hashFunction = hashFunction;
        this.zn = zn;
        this.longAesPseudoRandomFunction = new LongAesPseudoRandomFunction(
                new AesPseudorandomFunction(aesKeyLength),
                (zn.getCharacteristic().bitLength() + aesKeyLength + oversubscription + 1) / aesKeyLength  // Compute number of AES instances required to get desired output bit length
        );
        this.init();
    }

    public HashThenPrfToZn(Representation repr) {
        new ReprUtil(this).deserialize(repr);
        this.init();
    }

    /**
     * Initialization of HashTHenPrfToZn.
     */
    private void init() {
        BigInteger p = zn.getCharacteristic();

        // Compute quotient of prf output all 1s divided by p
        // We can use all remainders with quotients strictly smaller than that quotient to draw uniformly at random from Zp
        byte[] bytes = new byte[longAesPseudoRandomFunction.getKeyLengthBytes()];
        Arrays.fill(bytes, (byte) 255);

        BigInteger[] dar = new BigInteger(1, bytes).divideAndRemainder(p);
        this.maxQuotient = dar[0];
    }

    /**
     * Generates a PRF key that can be used to hash-then-prf to Zn
     *
     * @return a PRF key
     */
    public PrfKey generateKey() {
        return longAesPseudoRandomFunction.generateKey();
    }


    /**
     * Generate pseudorandom ZnVectors of variable size using unique prefixes for the vectorSize and index.
     *
     * @param prfKey     the PRF key
     * @param hashInput  input to hash
     * @param vectorSize target vector size
     * @param prefix     prefix to allow using the same vectorSize and preImage several times
     * @return a pseudorandom Vector of Zn elements
     */
    public Vector<Zn.ZnElement> hashThenPrfToZnVector(PrfKey prfKey, UniqueByteRepresentable hashInput, int vectorSize, String prefix) {
        Vector<Zn.ZnElement> result = new Vector<>(vectorSize);

        for (int i = 0; i < vectorSize; i++) {
            ByteArrayAccumulator accumulator = new ByteArrayAccumulator();
            accumulator.append(vectorSize); // Ensure uniqueness for each vector size, allows using the same preimage for several, different sized vectors
            accumulator.append(i); // Index to prevent having the same output for each element
            accumulator.escapeAndSeparate(prefix); // Prefix to allow using the same preImage and vectorSize twice
            accumulator.escapeAndAppend(hashInput);
            Zn.ZnElement element = hashThenPrfToZn(prfKey, accumulator.extractBytes());
            result.add(i, element);
        }

        return result;
    }

    /**
     * Main method of Hash-then-PRF to Zn.
     * Private to avoid accidentally mixing different hashInput formats.
     *
     * @param prfKey    the PRF key
     * @param hashInput input to hash
     * @return a pseudorandom Zn element
     */
    private Zn.ZnElement hashThenPrfToZn(PrfKey prfKey, byte[] hashInput) {
        BigInteger p = zn.getCharacteristic();

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

        if (quotientAndRemainder[0].compareTo(maxQuotient) >= 0) {
            throw new RuntimeException("PRF output is in the reject interval!");
        }

        return zn.valueOf(quotientAndRemainder[1]);
    }

    /*
     * Some wrappers with different method signatures.
     */

    public Vector<Zn.ZnElement> hashThenPrfToZnVector(PrfKey prfKey, UniqueByteRepresentable hashInput, int vectorSize) {
        return hashThenPrfToZnVector(prfKey, hashInput, vectorSize, "");
    }

    public Zn.ZnElement hashThenPrfToZn(PrfKey prfKey, UniqueByteRepresentable hashInput) {
        return hashThenPrfToZnVector(prfKey, hashInput, 1, "").get(0);
    }

    public Zn.ZnElement hashThenPrfToZn(PrfKey prfKey, UniqueByteRepresentable hashInput, String prefix) {
        return hashThenPrfToZnVector(prfKey, hashInput, 1, prefix).get(0);
    }


    public LongAesPseudoRandomFunction getLongAesPseudoRandomFunction() {
        return longAesPseudoRandomFunction;
    }

    public HashFunction getHashFunction() {
        return hashFunction;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HashThenPrfToZn prfToZn = (HashThenPrfToZn) o;
        return Objects.equals(longAesPseudoRandomFunction, prfToZn.longAesPseudoRandomFunction) && Objects.equals(hashFunction, prfToZn.hashFunction) && Objects.equals(zn, prfToZn.zn) && Objects.equals(maxQuotient, prfToZn.maxQuotient);
    }

    @Override
    public int hashCode() {
        return Objects.hash(longAesPseudoRandomFunction, hashFunction, zn, maxQuotient);
    }
}
