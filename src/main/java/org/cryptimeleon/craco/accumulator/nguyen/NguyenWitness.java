package org.cryptimeleon.craco.accumulator.nguyen;

import org.cryptimeleon.craco.accumulator.AccumulatorWitness;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

public class NguyenWitness implements AccumulatorWitness {
    private final GroupElement witness;

    public NguyenWitness(GroupElement witness) {
        this.witness = witness;
    }

    public NguyenWitness(Representation repr, Group group) {
        this.witness = group.restoreElement(repr);
    }

    public GroupElement getWitness() {
        return witness;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenWitness that = (NguyenWitness) o;
        return witness.equals(that.witness);
    }

    @Override
    public int hashCode() {
        return Objects.hash(witness);
    }

    @Override
    public Representation getRepresentation() {
        return witness.getRepresentation();
    }
}
