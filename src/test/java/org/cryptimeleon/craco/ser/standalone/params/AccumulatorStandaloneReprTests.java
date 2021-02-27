package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.accumulator.nguyen.NguyenAccumulatorScheme;
import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

public class AccumulatorStandaloneReprTests extends StandaloneReprSubTest {
    public void accumulator() {
        test(NguyenAccumulatorScheme.setup(new CountingBilinearGroup(128, BilinearGroup.Type.TYPE_3), 3));
    }
}
