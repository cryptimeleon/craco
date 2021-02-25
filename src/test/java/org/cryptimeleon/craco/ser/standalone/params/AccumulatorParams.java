package org.cryptimeleon.craco.ser.standalone.params;

import com.sun.tools.javac.util.List;
import org.cryptimeleon.craco.accumulator.nguyen.NguyenAccumulatorScheme;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import java.util.Collection;

public class AccumulatorParams {

    public static Collection<StandaloneTestParams> get() {
        return List.of(
                new StandaloneTestParams(NguyenAccumulatorScheme.setup(new CountingBilinearGroup(128, BilinearGroup.Type.TYPE_3), 3))
        );
    }


}
