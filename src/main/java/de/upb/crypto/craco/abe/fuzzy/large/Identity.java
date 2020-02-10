package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * An identity is a collection of {@link BigIntegerAttribute}
 *
 * @author Marius Dransfeld
 */
public class Identity implements StandaloneRepresentable, KeyIndex, CiphertextIndex, UniqueByteRepresentable {
    @UniqueByteRepresented
    private Set<BigIntegerAttribute> attributes;

    public Identity(Representation repr) {
        attributes = new HashSet<>();
        ListRepresentation listRepr = repr.obj().get("attributes").list();
        listRepr.forEach((value) -> attributes.add(new BigIntegerAttribute(value.bigInt().get())));
    }

    /**
     * Creates an empty identity
     */
    public Identity() {
        attributes = new HashSet<>();
    }

    /**
     * Creates an identity
     *
     * @param attributes initial attributes
     */
    public Identity(Collection<BigIntegerAttribute> attributes) {
        this.attributes = new HashSet<>();
        this.attributes.addAll(attributes);
    }

    /**
     * Creates an identity
     *
     * @param attributes initial attributes
     */
    public Identity(BigIntegerAttribute... attributes) {
        this.attributes = new HashSet<>();
        for (BigIntegerAttribute b : attributes) {
            this.attributes.add(b);
        }
    }

    /**
     * Adds a new attribute to this identity
     *
     * @param attribute new attribute
     */
    public void addAttribute(BigIntegerAttribute attribute) {
        attributes.add(attribute);
    }

    /**
     * Gets all attributes in this identity
     *
     * @return set of attributes
     */
    public Set<BigIntegerAttribute> getAttributes() {
        return attributes;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Identity) {
            Identity other = (Identity) obj;
            return other.attributes.equals(attributes);
        } else {
            return false;
        }
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation toReturn = new ObjectRepresentation();
        ListRepresentation list = new ListRepresentation();
        attributes.forEach((value) -> list.put(new BigIntegerRepresentation(value.getAttribute())));
        toReturn.put("attributes", list);
        return toReturn;
    }

    @Override
    public String toString() {
        Object[] array = attributes.toArray();
        Arrays.sort(array);
        return Arrays.toString(array);
    }

    @Override
    public int hashCode() {
        return attributes.hashCode();
    }

    public Identity intersect(Identity other) {
        Identity result = new Identity();
        for (BigIntegerAttribute i : attributes) {
            if (other.getAttributes().contains(i)) {
                result.addAttribute(i);
            }
        }
        return result;
    }

    /**
     * Creates a policy out of this identity
     *
     * @param threshold the amount of attributes in the intersection, that the policy
     *                  needs to be valid
     * @return
     */
    public Policy toPolicy(int threshold) {
        return new ThresholdPolicy(threshold, attributes);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
