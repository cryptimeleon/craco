package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.accumulator.nguyen.NguyenAccumulatorScheme;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import java.util.Arrays;
import java.util.Collection;

public class AccumulatorParams {

    public static Collection<StandaloneTestParams> get() {
        return Arrays.asList(
                new StandaloneTestParams(NguyenAccumulatorScheme.setup(new CountingBilinearGroup(128, BilinearGroup.Type.TYPE_3), 3))
        );
    }


}
