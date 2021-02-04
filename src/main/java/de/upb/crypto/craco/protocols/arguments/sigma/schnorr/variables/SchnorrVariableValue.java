package de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables;

import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

import java.math.BigInteger;

public interface SchnorrVariableValue extends Representable, UniqueByteRepresentable {
    /**
     * Returns a {@code SchnorrVariableValue} that is \(\text{factor} * \text{this} + \text{summand}\).
     */
    SchnorrVariableValue evalLinear(BigInteger factor, SchnorrVariableValue summand);

    SchnorrVariable getVariable();

    Expression asExpression();
}
