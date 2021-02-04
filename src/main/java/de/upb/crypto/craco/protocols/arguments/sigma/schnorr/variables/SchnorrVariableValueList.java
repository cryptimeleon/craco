package de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables;

import de.upb.crypto.craco.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.craco.protocols.arguments.sigma.Response;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

/**
 * Holds an ordered list of {@link SchnorrVariableValue}s.
 */
public class SchnorrVariableValueList implements SchnorrVariableAssignment, AnnouncementSecret, Response {
    private final LinkedHashMap<SchnorrVariable, SchnorrVariableValue> variableValues;

    public SchnorrVariableValueList(List<? extends SchnorrVariableValue> variableValues) {
        this.variableValues = new LinkedHashMap<>();
        for (SchnorrVariableValue val : variableValues)
            this.variableValues.put(val.getVariable(), val);
    }

    public SchnorrVariableValueList(List<? extends SchnorrVariable> variables, Representation repr) {
        int i=0;
        variableValues = new LinkedHashMap<>();
        for (SchnorrVariable variable : variables) {
            SchnorrVariableValue val = variable.recreateValue(repr.list().get(i++));
            variableValues.put(val.getVariable(), val);
        }
    }

    private SchnorrVariableValueList(LinkedHashMap<SchnorrVariable, SchnorrVariableValue> variableValues) {
        this.variableValues = variableValues;
    }

    /**
     * Creates the list by ordering the given values lexicographically by their name.
     * @param nameValueMap a map mapping variable names to their variable values
     */
    public SchnorrVariableValueList(Map<String, SchnorrVariableValue> nameValueMap) {
        this(nameValueMap.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(Map.Entry::getValue)
                .collect(Collectors.toList())
        );
    }

    @Override
    public SchnorrVariableValue getValue(SchnorrVariable variable) {
        return variableValues.get(variable);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        variableValues.forEach((k,v) -> accumulator.append(v));
        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        variableValues.values().stream()
                .map(Representable::getRepresentation)
                .forEachOrdered(repr::add);

        return repr;
    }

    public SchnorrVariableValueList map(BiFunction<SchnorrVariable, SchnorrVariableValue, SchnorrVariableValue> mapper) {
        LinkedHashMap<SchnorrVariable, SchnorrVariableValue> newValues = new LinkedHashMap<>();
        this.variableValues.forEach((k, v) -> newValues.put(k, mapper.apply(k, v)));

        return new SchnorrVariableValueList(newValues);
    }
}
