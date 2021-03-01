package org.cryptimeleon.craco.common.plaintexts;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

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
        p = baseGroup.restoreElement(repr);
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
