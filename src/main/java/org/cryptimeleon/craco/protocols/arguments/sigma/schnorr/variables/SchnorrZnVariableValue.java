package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables;

import org.cryptimeleon.math.expressions.Expression;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;
import java.util.Objects;

public class SchnorrZnVariableValue implements SchnorrVariableValue {
    protected final Zn.ZnElement value;
    protected final SchnorrZnVariable variable;

    public SchnorrZnVariableValue(Zn.ZnElement value, SchnorrZnVariable variable) {
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
    public SchnorrZnVariableValue evalLinear(BigInteger factor, SchnorrVariableValue summand) {
        return new SchnorrZnVariableValue(value.mul(factor).add(((SchnorrZnVariableValue) summand).value), variable);
    }

    @Override
    public SchnorrZnVariable getVariable() {
        return variable;
    }

    @Override
    public Expression asExpression() {
        return getValue().asExponentExpression();
    }

    public Zn.ZnElement getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SchnorrZnVariableValue that = (SchnorrZnVariableValue) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.append(value);
        return accumulator;
    }
}
