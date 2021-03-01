package org.cryptimeleon.craco.commitment.pedersen;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

public class PedersenCommitment implements Commitment {
    private final GroupElement commitment;

    public PedersenCommitment(GroupElement commitment) {
        this.commitment = commitment;
    }

    public GroupElement get() {
        return commitment;
    }

    @Override
    public Representation getRepresentation() {
        return commitment.getRepresentation();
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        return commitment.updateAccumulator(byteAccumulator);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PedersenCommitment that = (PedersenCommitment) o;
        return Objects.equals(commitment, that.commitment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commitment);
    }
}
