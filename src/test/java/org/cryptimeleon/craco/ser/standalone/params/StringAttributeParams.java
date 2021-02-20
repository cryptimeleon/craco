package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class StringAttributeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StringAttribute.class, new StringAttribute("A"));
    }

}
