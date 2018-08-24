package de.upb.crypto.craco.prf;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A pseudorandom function is a family of functions (f_k)
 * so that for random choice of the key k, f_k: X -> Y is computationally
 * indistinguishable from a uniformly random function F: X -> Y.
 * <p>
 * The way to use this interface is:
 * - generate a key k with generateKey()
 * - call evaluate(k, x) to receive y = f_k(x)
 */
public interface PseudorandomFunction extends StandaloneRepresentable {
    /**
     * Generates a key k for use with this prf
     */
    PrfKey generateKey();

    /**
     * Maps a preimage x to its image using key k
     *
     * @return f_k(x)
     */
    PrfImage evaluate(PrfKey k, PrfPreimage x);

    //below this, there are only serialization-related methods

    /**
     * Recreates (deserializes) a key k from its Representation
     */
    PrfKey getKey(Representation repr);

    /**
     * Recreates (deserializes) a preimage x from its Representation
     */
    PrfPreimage getPreimage(Representation repr);

    /**
     * Recreates (deserializes) an image y from its Representation.
     * (to map x to y, use the method "evaluate")
     */
    PrfImage getImage(Representation repr);
}
