package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.accumulator.nguyen.*;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

public class AccumulatorParams {

    public static Collection<StandaloneTestParams> get() {

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        NguyenAccumulatorPublicParametersGen nguyenAccumulatorPublicParametersGen = new
                NguyenAccumulatorPublicParametersGen();
        NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters = nguyenAccumulatorPublicParametersGen
                .setup(260, 20, true);
        toReturn.add(new StandaloneTestParams(NguyenWitness.class, new NguyenWitness
                (nguyenAccumulatorPublicParameters.getG_Tilde())));
        toReturn.add(new StandaloneTestParams(NguyenAccumulatorIdentity.class, new NguyenAccumulatorIdentity
                (nguyenAccumulatorPublicParameters.getUniverse().get(0).getIdentity())));
        toReturn.add(new StandaloneTestParams(NguyenAccumulatorValue.class, new NguyenAccumulatorValue
                (nguyenAccumulatorPublicParameters.getG_Tilde())));
        toReturn.add(new StandaloneTestParams(NguyenAccumulatorPublicParameters.class,
                nguyenAccumulatorPublicParameters));
        NguyenAccumulator accumulator = new NguyenAccumulator(nguyenAccumulatorPublicParameters);
        accumulator.create(new HashSet<>(Collections.singletonList(nguyenAccumulatorPublicParameters.getUniverse()
                .get(0))));
        toReturn.add(new StandaloneTestParams(NguyenAccumulator.class, accumulator));

        return toReturn;
    }


}
