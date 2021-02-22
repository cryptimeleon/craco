package org.cryptimeleon.craco.common.policies;

import org.cryptimeleon.craco.secretsharing.accessstructure.exceptions.WrongAccessStructureException;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * A Boolean policy consists of a Boolean operator and a set of policies.
 * <p>
 * To fulfill a Boolean policy,
 * <ul>
 *     <li> all the contained policies must be fulfilled in case of an AND operator,
 *     <li> one of the contained policies must be fulfilled in case of an OR operator.
 * </ul>
 */
public class BooleanPolicy implements Policy {

    /**
     * A Boolean operator, either AND or OR.
     */
    public enum BooleanOperator {
        AND, OR
    }

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
