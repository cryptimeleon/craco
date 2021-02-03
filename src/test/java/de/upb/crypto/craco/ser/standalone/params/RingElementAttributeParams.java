package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.RingElementAttribute;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.math.structures.rings.zn.Zp;

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
