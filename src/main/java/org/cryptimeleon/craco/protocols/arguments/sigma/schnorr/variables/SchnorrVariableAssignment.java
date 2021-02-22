package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables;

import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.math.expressions.Expression;
import org.cryptimeleon.math.expressions.Substitution;
import org.cryptimeleon.math.expressions.VariableExpression;

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
}
