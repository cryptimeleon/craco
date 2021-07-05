package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables;

import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.math.expressions.Expression;
import org.cryptimeleon.math.expressions.Substitution;
import org.cryptimeleon.math.expressions.VariableExpression;

import java.math.BigInteger;

public interface SchnorrVariableAssignment extends Substitution, SecretInput {
    SchnorrVariableAssignment EMPTY = new EmptyAssignment();

    class EmptyAssignment implements SchnorrVariableAssignment {
        private EmptyAssignment() {}

        @Override
        public SchnorrVariableValue getValue(SchnorrVariable variable) {
            return null;
        }
    }

    SchnorrVariableValue getValue(SchnorrVariable variable);

    default Expression getSubstitution(VariableExpression variable) {
        if (!(variable instanceof SchnorrVariable))
            return null;

        SchnorrVariableValue val = getValue((SchnorrVariable) variable);
        if (val == null)
            return null;
        return val.asExpression();
    }

    default SchnorrVariableAssignment fallbackTo(SchnorrVariableAssignment fallback) {
        return new SchnorrVariableValueHierarchy(this, fallback);
    }

    /**
     * Computes this * challenge + random
     */
    default SchnorrVariableAssignment evalLinear(BigInteger challenge, SchnorrVariableAssignment random) {
        return new SchnorrVariableAssignment() {
            @Override
            public SchnorrVariableValue getValue(SchnorrVariable variable) {
                return SchnorrVariableAssignment.this.getValue(variable).evalLinear(challenge, random.getValue(variable));
            }
        };
    }
}

