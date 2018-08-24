package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.common.WatersHash;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;

public class WatersHashParams {
    public static StandaloneTestParams get() {
        BilinearGroupFactory fac = new BilinearGroupFactory(80);
        fac.setDebugMode(true);
        fac.setRequirements(BilinearGroup.Type.TYPE_1);
        BilinearGroup group = fac.createBilinearGroup();
        return new StandaloneTestParams(WatersHash.class, new WatersHash(group.getG1(), 10));
    }
}
