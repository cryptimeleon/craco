package de.upb.crypto.craco.common;

import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * A plaintext consisting of a single group element.
 */
public class GroupElementPlainText implements PlainText, UniqueByteRepresentable {

    @UniqueByteRepresented
    private final GroupElement p;

    public GroupElementPlainText(GroupElement elem) {
        p = elem;
    }

    /**
     * Reconstructs this group element plaintext from the given representation using the given group
     * as the restorer.
     *
     * @param repr the representation to restore from
     * @param baseGroup the group to use as restorer; should be the group that contains the group element
     */
    public GroupElementPlainText(Representation repr, Group baseGroup) {
        p = baseGroup.getElement(repr);
    }

    /**
     * Returns the group element represented by this plaintext.
     */
    public GroupElement get() {
        return p;
    }

    @Override
    public Representation getRepresentation() {
        return p.getRepresentation();
    }

    @Override
    public String toString() {
        return getRepresentation().toString();
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(p);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        GroupElementPlainText other = (GroupElementPlainText) obj;
        return Objects.equals(p, other.p);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
