package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.interfaces.AccumulatorValue;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

/**
 * An accumulator value for the Nguyen accumulator scheme, i.e. a short representation of a set.
 * the value is g^(\prod (x_i + secret))
 */
public class NguyenAccumulatorValue implements AccumulatorValue {
    @Represented(structure = "group", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement value;

    @Represented
    private Group group;

    public NguyenAccumulatorValue(GroupElement value) {
        this.value = value;
        this.group = value.getStructure();
    }

    public NguyenAccumulatorValue(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public GroupElement getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof NguyenAccumulatorValue)) return false;

        NguyenAccumulatorValue that = (NguyenAccumulatorValue) o;

        if (!getValue().equals(that.getValue())) return false;
        return group.equals(that.group);
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
