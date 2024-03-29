package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.accumulator.nguyen.NguyenAccumulatorScheme;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

public class AccumulatorStandaloneReprTests extends StandaloneReprSubTest {
    public void accumulator() {
        test(NguyenAccumulatorScheme.setup(new DebugBilinearGroup(BilinearGroup.Type.TYPE_3), 3));
    }
}
