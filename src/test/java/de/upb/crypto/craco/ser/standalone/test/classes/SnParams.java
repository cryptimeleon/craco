package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.structures.groups.sn.Sn;

public class SnParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(Sn.class, new Sn(17));
    }
}
