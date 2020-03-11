package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.interfaces.AccumulatorWitness;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

public class NguyenWitness implements AccumulatorWitness {
    @Represented(structure = "group", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement value;

    @Represented
    private Group group;

    public NguyenWitness(GroupElement value) {
        this.value = value;
        this.group = value.getStructure();
    }

    public NguyenWitness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
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
        if (!(o instanceof NguyenWitness)) return false;

        NguyenWitness that = (NguyenWitness) o;

        if (!value.equals(that.value)) return false;
        return group.equals(that.group);
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
