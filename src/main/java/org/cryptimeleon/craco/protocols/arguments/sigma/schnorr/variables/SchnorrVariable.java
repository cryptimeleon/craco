package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables;

import org.cryptimeleon.math.expressions.VariableExpression;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;

/**
 * <p>A variable in the context of SchnorrFragments.</p>
 *
 * <p>This is only the (static) variable. SchnorrVariableValue represents a concrete value.</p>
 *
 * <p>
 * Variables are named only for debuggability.<br>
 * Two variables are equal iff they are the same object.
 * </p>
 */
public abstract class SchnorrVariable implements RepresentationRestorer, VariableExpression {
    public final String name;

    public SchnorrVariable(String name) {
        this.name = name;
    }

    public abstract SchnorrVariableValue generateRandomValue();
    public abstract SchnorrVariableValue restoreValue(Representation repr);

    @Override
    public Object recreateFromRepresentation(Type type, Representation repr) {
        if (!(type instanceof Class))
            throw new IllegalArgumentException("Cannot recreate "+type.getTypeName());

        if (SchnorrVariableValue.class.isAssignableFrom((Class) type))
            return restoreValue(repr);

        throw new IllegalArgumentException("Cannot recreate "+type.getTypeName());
    }

    @Override
    public boolean equals(Object o) {
        return this == o;
    }

    @Override
    public int hashCode() {
        return System.identityHashCode(this);
    }

    @Override
    public String toString() {
        return name;
    }
}
