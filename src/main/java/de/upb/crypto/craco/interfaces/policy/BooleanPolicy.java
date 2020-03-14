package de.upb.crypto.craco.interfaces.policy;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedSet;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class BooleanPolicy implements Policy {

    public enum BooleanOperator {
        AND, OR
    }

    ;

    @UniqueByteRepresented
    @Represented
    private BooleanOperator operator;

    @UniqueByteRepresented
    @Represented
    private HashSet<Policy> children;

    public BooleanPolicy(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public BooleanPolicy(BooleanOperator operator, Collection<? extends Policy> children) {
        this.operator = operator;
        this.children = new HashSet<>();
        this.children.addAll(children);
    }

    public BooleanPolicy(BooleanOperator operator, Policy... children) {
        this(operator, Arrays.asList(children));
    }

    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> facts) throws WrongAccessStructureException {
        int fulfilled = 0;
        for (Policy policy : children) {
            fulfilled += policy.isFulfilled(facts) ? 1 : 0;
        }
        if (operator == BooleanOperator.AND)
            return fulfilled >= children.size();
        else
            return fulfilled >= 1;
    }

    public BooleanOperator getOperator() {
        return operator;
    }

    public Set<Policy> getChildren() {
        return new HashSet<>(children);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((children == null) ? 0 : children.hashCode());
        result = prime * result + operator.ordinal();
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
        BooleanPolicy other = (BooleanPolicy) obj;
        if (children == null) {
            if (other.children != null)
                return false;
        } else {
            if (!children.containsAll(other.children))
                return false;
            if (!other.children.containsAll(children))
                return false;
        }
        if (operator != other.operator)
            return false;
        return true;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}
