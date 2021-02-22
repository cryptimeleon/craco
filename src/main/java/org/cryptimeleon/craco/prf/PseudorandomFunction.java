package org.cryptimeleon.craco.prf;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;

/**
 * A pseudorandom function is a family of functions \((f_k)\)
 * so that for random choice of the key k, \(f_k: X \rightarrow Y\) is computationally
 * indistinguishable from a uniformly random function \(F: X \rightarrow Y\).
 * <p>
 * The way to use this interface is:
 * <ol>
 * <li> Generate a key k using {@link #generateKey()}
 * <li> Call {@link #evaluate(PrfKey, PrfPreimage)} using key k and input x to receive \(y = f_k(x)\)
 * </ol>
 */
public interface PseudorandomFunction extends StandaloneRepresentable {
    /**
     * Generates a key k for use with this PRF.
     */
    PrfKey generateKey();

    /**
     * Maps a preimage x to its image using key k.
     *
     * @return output of \(f_k(x)\)
     */
    PrfImage evaluate(PrfKey k, PrfPreimage x);

    //below this, there are only serialization-related methods

    /**
     * Recreates (deserializes) a key k from its Representation.
     */
    PrfKey getKey(Representation repr);

    /**
     * Recreates (deserializes) a preimage x from its Representation.
     */
    PrfPreimage getPreimage(Representation repr);

    /**
     * Recreates (deserializes) an image y from its Representation.
     */
    PrfImage getImage(Representation repr);
}
