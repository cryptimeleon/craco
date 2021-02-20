package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables;

import org.cryptimeleon.math.expressions.Expression;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;

import java.math.BigInteger;

public interface SchnorrVariableValue extends Representable, UniqueByteRepresentable {
    /**
     * Returns a {@code SchnorrVariableValue} that is \(\text{factor} * \text{this} + \text{summand}\).
     */
    SchnorrVariableValue evalLinear(BigInteger factor, SchnorrVariableValue summand);

    SchnorrVariable getVariable();

    Expression asExpression();
}
