package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.interfaces.abe.RingElementAttribute;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class RingElementAttributeParams {
    public static StandaloneTestParams get() {
        Zp zp = new Zp(BigInteger.valueOf(17));
        return new StandaloneTestParams(RingElementAttribute.class, new RingElementAttribute((RingElement) zp
                .getUniformlyRandomElement()));
    }
}
