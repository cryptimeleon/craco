package org.cryptimeleon.craco.prf.zn;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.prf.PrfImage;
import org.cryptimeleon.craco.prf.PrfKey;
import org.cryptimeleon.craco.prf.PrfPreimage;
import org.cryptimeleon.craco.prf.PseudorandomFunction;
import org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Arrays;
import java.util.Objects;

/**
 * AES based PRF with k key length and output length of the underlying AES key length.
 * PRF_k(x) = AES_k1(x)||AES_k2(x)|..." with key k=(k1,k2,...)
 *
 * This is basically a wrapper around AesPseudorandomFunction.
 **/
public class LongAesPseudoRandomFunction implements PseudorandomFunction {

    @Represented
    private AesPseudorandomFunction aesPseudorandomFunction;
    @Represented
    private Integer factor;
    private int preimageLength; // In bytes
    private int keyLength;      // In bytes


    /**
     * Instantiates the PRF with an AES instance and desired factor.
     *
     * @param k                       factor by which output and key size of AES is increased
     * @param aesPseudorandomFunction AES instance to use k times
     */
    public LongAesPseudoRandomFunction(AesPseudorandomFunction aesPseudorandomFunction, int k) {
        this.aesPseudorandomFunction = aesPseudorandomFunction;
        this.factor = k;
        this.init();
    }

    public LongAesPseudoRandomFunction(Representation repr) {
        new ReprUtil(this).deserialize(repr);
        this.init();
    }

    private void init() {
        this.preimageLength = aesPseudorandomFunction.getKeylength() / 8;
        this.keyLength = preimageLength * factor;
    }

    @Override
    public PrfKey generateKey() {
        return ByteArrayImplementation.fromRandom(keyLength);
    }

    @Override
    public PrfImage evaluate(PrfKey k, PrfPreimage x) {
        if (((ByteArrayImplementation) k).length() != keyLength)
            throw new IllegalArgumentException("key k in the AES PRF has invalid length");
        if (((ByteArrayImplementation) x).length() != preimageLength)
            throw new IllegalArgumentException("preimage x in the AES PRF has invalid length");

        ByteArrayImplementation result = new ByteArrayImplementation(new byte[keyLength]);
        for (int i = 0; i <= factor; i++) {
            ByteArrayImplementation ki = new ByteArrayImplementation(Arrays.copyOfRange(k.getUniqueByteRepresentation(), i * preimageLength, (i + 1) * preimageLength));
            byte[] bytesToAppend = aesPseudorandomFunction.evaluate(ki, x).getUniqueByteRepresentation();
            result.append(new ByteArrayImplementation(bytesToAppend));
        }
        return result;
    }


    @Override
    public PrfKey restoreKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public PrfPreimage restorePreimage(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public PrfImage restoreImage(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LongAesPseudoRandomFunction that = (LongAesPseudoRandomFunction) o;
        return factor == that.factor && preimageLength == that.preimageLength && keyLength == that.keyLength && Objects.equals(aesPseudorandomFunction, that.aesPseudorandomFunction);
    }

    @Override
    public int hashCode() {
        return Objects.hash(aesPseudorandomFunction, factor, preimageLength, keyLength);
    }
}
