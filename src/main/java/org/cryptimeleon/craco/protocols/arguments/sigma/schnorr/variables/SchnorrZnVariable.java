package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables;

import org.cryptimeleon.math.expressions.exponent.ExponentVariableExpr;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class SchnorrZnVariable extends SchnorrVariable implements ExponentVariableExpr {
    public final Zn zn;

    public SchnorrZnVariable(String name, Zn zn) {
        super(name);
        this.zn = zn;
    }

    @Override
    public SchnorrZnVariableValue generateRandomValue() {
        return new SchnorrZnVariableValue(zn.getUniformlyRandomElement(), this);
    }

    @Override
    public SchnorrZnVariableValue restoreValue(Representation repr) {
        return new SchnorrZnVariableValue(zn.getElement(repr), this);
    }
}
