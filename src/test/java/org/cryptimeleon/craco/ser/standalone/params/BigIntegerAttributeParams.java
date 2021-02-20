package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class BigIntegerAttributeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(BigIntegerAttribute.class, new BigIntegerAttribute(5));
    }

}
