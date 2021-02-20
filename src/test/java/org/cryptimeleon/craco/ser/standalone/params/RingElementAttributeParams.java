package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.RingElementAttribute;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.math.BigInteger;

public class RingElementAttributeParams {
    public static StandaloneTestParams get() {
        Zp zp = new Zp(BigInteger.valueOf(17));
        return new StandaloneTestParams(
                RingElementAttribute.class, 
                new RingElementAttribute(zp.getUniformlyRandomElement())
        );
    }
}
