package de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables;

import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;
import java.util.Objects;

public class SchnorrGroupElemVariableValue implements SchnorrVariableValue {
    protected final GroupElement value;
    protected final SchnorrGroupElemVariable variable;

    public SchnorrGroupElemVariableValue(GroupElement value, SchnorrGroupElemVariable variable) {
        this.value = value;
        if (value == null)
            throw new NullPointerException();
        this.variable = variable;
    }

    @Override
    public Representation getRepresentation() {
        return value.getRepresentation();
    }

    @Override
    public SchnorrGroupElemVariableValue evalLinear(BigInteger factor, SchnorrVariableValue summand) {
        return new SchnorrGroupElemVariableValue(value.pow(factor).op(((SchnorrGroupElemVariableValue) summand).value), variable);
    }

    @Override
    public SchnorrVariable getVariable() {
        return variable;
    }

    @Override
    public GroupElementExpression asExpression() {
        return getValue().expr();
    }

    public GroupElement getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SchnorrGroupElemVariableValue that = (SchnorrGroupElemVariableValue) o;
        return value.equals(that.value) &&
                Objects.equals(variable, that.variable);
    }

    @Override
    public int hashCode() {
        return Objects.hash(variable);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.append(value);
        return accumulator;
    }
}
