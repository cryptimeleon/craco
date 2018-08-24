package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class StringAttributeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StringAttribute.class, new StringAttribute("A"));
    }

}
