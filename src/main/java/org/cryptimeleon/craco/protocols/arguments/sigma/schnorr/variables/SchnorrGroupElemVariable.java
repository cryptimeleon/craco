package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables;

import org.cryptimeleon.math.expressions.group.GroupVariableExpr;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;

public class SchnorrGroupElemVariable extends SchnorrVariable implements GroupVariableExpr {
    protected Group group;

    public SchnorrGroupElemVariable(String name, Group group) {
        super(name);
        this.group = group;
    }

    @Override
    public SchnorrGroupElemVariableValue generateRandomValue() {
        return new SchnorrGroupElemVariableValue(group.getUniformlyRandomElement(), this);
    }

    @Override
    public SchnorrGroupElemVariableValue restoreValue(Representation repr) {
        return new SchnorrGroupElemVariableValue(group.getElement(repr), this);
    }
}
