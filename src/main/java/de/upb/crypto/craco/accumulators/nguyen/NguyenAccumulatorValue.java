package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.de.upb.crypto.craco.interfaces.AccumulatorValue;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * An accumulator value for the Nguyen accumulator scheme, a short representation of a set.
 * The value is \(g^(\prod (x_i + secret))\).
 */
public class NguyenAccumulatorValue implements AccumulatorValue {
    @Represented(restorer = "group")
    private GroupElement value;

    @Represented
    private Group group;

    public NguyenAccumulatorValue(GroupElement value) {
        this.value = value;
        this.group = value.getStructure();
    }

    public NguyenAccumulatorValue(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public GroupElement getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenAccumulatorValue other = (NguyenAccumulatorValue) o;
        return Objects.equals(value, other.value)
                && Objects.equals(group, other.group);
    }

    @Override
    public int hashCode() {
        int result = getValue().hashCode();
        result = 31 * result + group.hashCode();
        return result;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
