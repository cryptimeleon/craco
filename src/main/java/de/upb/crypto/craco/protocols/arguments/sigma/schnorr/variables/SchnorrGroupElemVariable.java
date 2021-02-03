package de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables;

import de.upb.crypto.math.expressions.group.GroupVariableExpr;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.serialization.Representation;

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
    public SchnorrGroupElemVariableValue recreateValue(Representation repr) {
        return new SchnorrGroupElemVariableValue(group.getElement(repr), this);
    }
}
