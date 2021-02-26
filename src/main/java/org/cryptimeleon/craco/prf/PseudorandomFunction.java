package org.cryptimeleon.craco.prf;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;

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
public interface PseudorandomFunction extends StandaloneRepresentable, RepresentationRestorer {
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
     * Restores a key k from its representation.
     */
    PrfKey restoreKey(Representation repr);

    /**
     * Restores a preimage x from its representation.
     */
    PrfPreimage restorePreimage(Representation repr);

    /**
     * Restores an image y from its representation.
     */
    PrfImage restoreImage(Representation repr);

    default Object restoreFromRepresentation(Type type, Representation repr) {
        if (type instanceof Class) {
            if (PrfKey.class.isAssignableFrom((Class) type)) {
                return this.restoreKey(repr);
            } else if (PrfPreimage.class.isAssignableFrom((Class) type)) {
                return this.restorePreimage(repr);
            } else if (PrfImage.class.isAssignableFrom((Class) type)) {
                return this.restoreImage(repr);
            }
        }
        throw new IllegalArgumentException("Cannot recreate object of type: " + type.getTypeName());
    }
}
