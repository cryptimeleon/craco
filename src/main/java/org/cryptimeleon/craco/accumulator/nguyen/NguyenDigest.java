package org.cryptimeleon.craco.accumulator.nguyen;

import org.cryptimeleon.craco.accumulator.AccumulatorDigest;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * A digest of the Nguyen accumulator scheme, a short representation of a set.
 * The value is \(g^(\prod (x_i + secret))\).
 */
public class NguyenDigest implements AccumulatorDigest {
    private final GroupElement digest;

    public NguyenDigest(GroupElement digest) {
        this.digest = digest;
    }

    public NguyenDigest(Representation repr, Group group) {
        this.digest = group.restoreElement(repr);
    }

    public GroupElement getDigest() {
        return digest;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenDigest that = (NguyenDigest) o;
        return digest.equals(that.digest);
    }

    @Override
    public int hashCode() {
        return Objects.hash(digest);
    }

    @Override
    public Representation getRepresentation() {
        return digest.getRepresentation();
    }
}
