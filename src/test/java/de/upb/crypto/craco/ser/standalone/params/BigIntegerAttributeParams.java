package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.BigIntegerAttribute;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class BigIntegerAttributeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(BigIntegerAttribute.class, new BigIntegerAttribute(5));
    }

}
