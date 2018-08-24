package de.upb.crypto.craco.interfaces.abe;

import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class SetOfAttributes implements KeyIndex, CiphertextIndex, Set<Attribute>, UniqueByteRepresentable {
    @UniqueByteRepresented
    private Set<Attribute> attributes = new HashSet<>();

    public SetOfAttributes() {

    }

    public SetOfAttributes(Collection<? extends Attribute> attributes) {
        this.attributes.addAll(attributes);
    }

    public SetOfAttributes(Attribute... attributes) {
        for (Attribute a : attributes) {
            this.attributes.add(a);
        }
    }

    public SetOfAttributes(Representation repr) {
        repr.list().forEach(r -> attributes.add((Attribute) r.repr().recreateRepresentable()));
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation result = new ListRepresentation();
        attributes.stream().map(attr -> new RepresentableRepresentation(attr)).forEach(result::put);

        return result;
    }

    @Override
    public boolean add(Attribute m) {
        return attributes.add(m);
    }

    @Override
    public boolean addAll(Collection<? extends Attribute> c) {
        return attributes.addAll(c);
    }

    @Override
    public void clear() {
        attributes.clear();
    }

    @Override
    public boolean contains(Object o) {
        return attributes.contains(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return attributes.containsAll(c);
    }

    @Override
    public boolean isEmpty() {
        return attributes.isEmpty();
    }

    @Override
    public Iterator<Attribute> iterator() {
        return attributes.iterator();
    }

    @Override
    public boolean remove(Object o) {
        return attributes.remove(o);
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        return attributes.removeAll(c);
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        return attributes.retainAll(c);
    }

    @Override
    public int size() {
        return attributes.size();
    }

    @Override
    public Object[] toArray() {
        return attributes.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return attributes.toArray(a);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
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
        SetOfAttributes other = (SetOfAttributes) obj;
        if (attributes == null) {
            if (other.attributes != null)
                return false;
        } else {
            if (!attributes.containsAll(other.attributes))
                return false;
            if (!other.attributes.containsAll(attributes))
                return false;
        }
        return true;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("[");
        for (Attribute a : attributes) {
            builder.append(a.toString());
            builder.append(", ");
        }
        builder.deleteCharAt(builder.length() - 1);
        builder.deleteCharAt(builder.length() - 1);
        builder.append("]");
        return builder.toString();
    }

}
