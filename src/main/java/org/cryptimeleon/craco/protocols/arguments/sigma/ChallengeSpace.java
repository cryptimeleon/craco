package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.craco.accumulator.AccumulatorDigest;
import org.cryptimeleon.craco.accumulator.AccumulatorWitness;
import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;
import java.math.BigInteger;

public interface ChallengeSpace extends RepresentationRestorer {
    Challenge generateRandomChallenge();

    /**
     * Returns the size of the challenge space. null for infinite size, throws {@link UnsupportedOperationException} if unknown.
     */
    BigInteger size() throws UnsupportedOperationException;

    /**
     * Restores a given challenge from representation.
     */
    Challenge restoreChallenge(Representation repr);

    default Object restoreFromRepresentation(Type type, Representation repr) {
        if (type instanceof Class && Challenge.class.isAssignableFrom((Class) type))
            return restoreChallenge(repr);

        throw new IllegalArgumentException("ChallengeSpace cannot restore type "+type.getTypeName()+" from representation");
    }

    /**
     * Creates a challenge from the given {@code byte[]}.
     * <p>
     * Given two random byte[] of the same (arbitrary) length, it should be unlikely that their challenge collides.
     * </p>
     */
    Challenge mapIntoChallengeSpace(byte[] bytes);

    /**
     * Hashes the given bytes into this challenge space (in a random-oracle-like manner).
     * If two challenge spaces are equal, then the behavior of this method is consistent.
     */
    Challenge hashIntoChallengeSpace(byte[] bytes);
}
