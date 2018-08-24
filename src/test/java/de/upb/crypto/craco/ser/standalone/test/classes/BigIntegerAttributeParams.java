package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.interfaces.abe.BigIntegerAttribute;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class BigIntegerAttributeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(BigIntegerAttribute.class, new BigIntegerAttribute(5));
    }

}
