package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.de.upb.crypto.craco.interfaces.AccumulatorWitness;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;

import java.util.Objects;

public class NguyenWitness implements AccumulatorWitness {
    @Represented(restorer = "group")
    private GroupElement value;

    @Represented
    private Group group;

    public NguyenWitness(GroupElement value) {
        this.value = value;
        this.group = value.getStructure();
    }

    public NguyenWitness(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public GroupElement getValue() {
        return value;
    }

    public void setValue(GroupElement value) {
        this.value = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenWitness other = (NguyenWitness) o;
        return Objects.equals(value, other.value)
                && Objects.equals(group, other.group);
    }

    @Override
    public int hashCode() {
        int result = value.hashCode();
        result = 31 * result + group.hashCode();
        return result;
    }

    @Override
    public String getName() {
        return "NguyenWitness-" + value;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
