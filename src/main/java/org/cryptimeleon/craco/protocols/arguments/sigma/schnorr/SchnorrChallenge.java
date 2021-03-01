package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr;

import org.cryptimeleon.craco.protocols.arguments.sigma.Challenge;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.serialization.BigIntegerRepresentation;
import org.cryptimeleon.math.serialization.Representation;

import java.math.BigInteger;
import java.util.Objects;

public class SchnorrChallenge implements Challenge {
    protected BigInteger challenge;

    public SchnorrChallenge(Representation repr) {
        challenge = repr.bigInt().get();
    }

    public SchnorrChallenge(BigInteger challenge) {
        this.challenge = challenge;
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    @Override
    public Representation getRepresentation() {
        return new BigIntegerRepresentation(challenge);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.append(challenge.toByteArray());
        return byteAccumulator;
    }

    public static SchnorrChallenge random(BigInteger challengeSpaceSize) {
        return new SchnorrChallenge(RandomGenerator.getRandomNumber(challengeSpaceSize));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SchnorrChallenge that = (SchnorrChallenge) o;
        return challenge.equals(that.challenge);
    }

    @Override
    public int hashCode() {
        return Objects.hash(challenge);
    }
}
