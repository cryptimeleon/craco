package de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables;

import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.rings.zn.Zn;

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
    public SchnorrZnVariableValue recreateValue(Representation repr) {
        return new SchnorrZnVariableValue(zn.getElement(repr), this);
    }
}
