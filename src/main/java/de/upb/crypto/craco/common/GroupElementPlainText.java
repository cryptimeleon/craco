package de.upb.crypto.craco.common;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

public class GroupElementPlainText implements PlainText, UniqueByteRepresentable {

    @UniqueByteRepresented
    private GroupElement p;

    public GroupElementPlainText(GroupElement elem) {
        p = elem;
    }

    public GroupElementPlainText(Representation repr, Group baseGroup) {
        p = baseGroup.getElement(repr);
    }

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
        final int prime = 31;
        int result = 1;
        result = prime * result + ((p == null) ? 0 : p.hashCode());
        return result;
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
