package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.common.WatersHash;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;

public class WatersHashParams {
    public static StandaloneTestParams get() {
        BilinearGroup group = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_1);
        return new StandaloneTestParams(WatersHash.class, new WatersHash(group.getG1(), 10));
    }
}
