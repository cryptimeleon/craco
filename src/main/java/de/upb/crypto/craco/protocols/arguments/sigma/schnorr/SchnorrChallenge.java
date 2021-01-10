package de.upb.crypto.craco.protocols.arguments.sigma.schnorr;

import de.upb.crypto.craco.protocols.arguments.sigma.Challenge;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.random.interfaces.RandomGeneratorSupplier;
import de.upb.crypto.math.serialization.BigIntegerRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;

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
        return new SchnorrChallenge(RandomGeneratorSupplier.getRnd().getRandomElement(challengeSpaceSize));
    }
}
