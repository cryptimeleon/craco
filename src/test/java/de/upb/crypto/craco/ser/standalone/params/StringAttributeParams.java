package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class StringAttributeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StringAttribute.class, new StringAttribute("A"));
    }

}
