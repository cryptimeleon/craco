package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.interfaces.RingElementAttribute;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.structures.rings.RingElement;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.math.BigInteger;

public class RingElementAttributeParams {
    public static StandaloneTestParams get() {
        Zp zp = new Zp(BigInteger.valueOf(17));
        return new StandaloneTestParams(RingElementAttribute.class, new RingElementAttribute((RingElement) zp
                .getUniformlyRandomElement()));
    }
}
