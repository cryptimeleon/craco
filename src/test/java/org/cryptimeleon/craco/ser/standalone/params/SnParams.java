package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.structures.groups.sn.Sn;

public class SnParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(Sn.class, new Sn(17));
    }
}
