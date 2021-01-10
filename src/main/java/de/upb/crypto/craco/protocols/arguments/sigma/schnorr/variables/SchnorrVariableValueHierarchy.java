package de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables;

public class SchnorrVariableValueHierarchy implements SchnorrVariableAssignment {
    private final SchnorrVariableAssignment tryFirst;
    private final SchnorrVariableAssignment tryThen;

    public SchnorrVariableValueHierarchy(SchnorrVariableAssignment tryFirst, SchnorrVariableAssignment tryThen) {
        this.tryFirst = tryFirst;
        this.tryThen = tryThen;
    }

    @Override
    public SchnorrVariableValue getValue(SchnorrVariable variable) {
        SchnorrVariableValue val1 = tryFirst.getValue(variable);
        if (val1 != null)
            return val1;
        return tryThen.getValue(variable);
    }
}
