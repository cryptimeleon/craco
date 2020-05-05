package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.SymmetricKey;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Arrays;

/**
 * A basic approach of a {@link KeyDerivationFunction} using a hash function. This class can be used to generate key
 * derivation functions that are not provably secure (e.g. using {@link SHA256HashFunction} as a hash function), or
 * it can be used to generate provably secure key derivation functions. For this, you have to setup a
 *
 * @author Jan
 */
public class HashBasedKeyDerivationFunction implements KeyDerivationFunction<SymmetricKey> {

    @Represented
    private HashFunction hashFunction;

    public HashBasedKeyDerivationFunction(HashFunction hashFunction) {
        this.hashFunction = hashFunction;
    }

    /**
     * This doesn't yield provable security.
     */
    public HashBasedKeyDerivationFunction() {
        this(new SHA256HashFunction());
    }

    public HashBasedKeyDerivationFunction(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public SymmetricKey deriveKey(KeyMaterial material) {
        byte[] hashedPlainText = hashFunction.hash(material);
        return new ByteArrayImplementation(Arrays.copyOfRange(hashedPlainText, 0, 128 / 8));
    }


    /**
     * Returns the output-length in bytes
     *
     * @return
     */
    public int bitSize() {
        return hashFunction.getOutputLength();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((hashFunction == null) ? 0 : hashFunction.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HashBasedKeyDerivationFunction other = (HashBasedKeyDerivationFunction) obj;
        if (hashFunction == null) {
            return other.hashFunction == null;
        } else return hashFunction.equals(other.hashFunction);
    }

}
