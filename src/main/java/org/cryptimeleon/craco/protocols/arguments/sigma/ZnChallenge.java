package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;

public class ZnChallenge implements Challenge {
    protected Zn.ZnElement challenge;

    public ZnChallenge(Zn.ZnElement challenge) {
        this.challenge = challenge;
    }

    public BigInteger getChallenge() {
        return challenge.asInteger();
    }

    @Override
    public Representation getRepresentation() {
        return challenge.getRepresentation();
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.append(challenge);
        return byteAccumulator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZnChallenge that = (ZnChallenge) o;
        return challenge.equals(that.challenge);
    }

    @Override
    public int hashCode() {
        return challenge.hashCode();
    }

    @Override
    public ChallengeSpace getChallengeSpace() {
        return new ZnChallengeSpace(challenge.getStructure());
    }
}
