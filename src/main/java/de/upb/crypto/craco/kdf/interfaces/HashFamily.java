package de.upb.crypto.craco.kdf.interfaces;

import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.structures.polynomial.Seed;

/**
 * A family of hash functions \(\{H_k: \{0,1\}^n \rightarrow \{0,1\}^m\}_{k \in \{0,1\}^d}\)
 * where \(d\) denotes the key length, \(n\) the input length and \(m\) the output length.
 *
 *
 */
public interface HashFamily extends StandaloneRepresentable {

    /**
     * Returns the input length in number of bits.
     */
    public int getInputLength();

    /**
     * Returns the output length in number of bits.
     */
    public int getOutputLength();

    /**
     * Returns the seed (key) length in number of bits.
     */
    public int seedLength();

    /**
     * Returns a function specified by the key.
     *
     * @param seed the key of the function
     * @return the hash function corresponding to the key {@code seed}
     */
    public HashFunction seedFunction(Seed seed);

    /**
     * Deserializes a representation of a hash function.
     *
     * @param repr the serialized hash function
     * @return the deserialized hash function
     */
    public HashFunction getHashFunction(Representation repr);
}
