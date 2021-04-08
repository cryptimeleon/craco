package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.HashIntoStructure;
import org.cryptimeleon.math.structures.rings.zn.HashIntoZn;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A challenge space where elements can be interpreted as integers 0, 1, ... size()-1.
 */
public class ZnChallengeSpace implements ChallengeSpace {
    protected Zn zn;

    public ZnChallengeSpace(Zn zn) {
        this.zn = zn;
    }

    public ZnChallengeSpace(BigInteger size) {
        this.zn = new Zn(size);
    }

    @Override
    public ZnChallenge generateRandomChallenge() {
        return new ZnChallenge(zn.getUniformlyRandomElement());
    }

    @Override
    public BigInteger size() throws UnsupportedOperationException {
        return zn.size();
    }

    @Override
    public ZnChallenge restoreChallenge(Representation repr) {
        return new ZnChallenge(zn.restoreElement(repr));
    }

    @Override
    public ZnChallenge mapIntoChallengeSpace(byte[] bytes) {
        return new ZnChallenge(zn.valueOf(bytes));
    }

    @Override
    public ZnChallenge hashIntoChallengeSpace(byte[] bytes) {
        return new ZnChallenge(new HashIntoZn(zn).hash(bytes));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZnChallengeSpace that = (ZnChallengeSpace) o;
        return zn.equals(that.zn);
    }

    @Override
    public int hashCode() {
        return Objects.hash(zn);
    }
}
