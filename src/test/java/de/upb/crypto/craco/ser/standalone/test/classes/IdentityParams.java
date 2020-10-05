package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.fuzzy.large.Identity;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class IdentityParams {
    public static StandaloneTestParams get() {
        Identity id = new Identity(new BigIntegerAttribute(1), new BigIntegerAttribute(2), new BigIntegerAttribute(4));
        return new StandaloneTestParams(Identity.class, id);
    }

}
