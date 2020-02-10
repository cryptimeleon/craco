package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.policy.BooleanPolicy;
import de.upb.crypto.craco.common.interfaces.policy.BooleanPolicy.BooleanOperator;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class BooleanPolicyParams {

    public static StandaloneTestParams get() {
        return new StandaloneTestParams(BooleanPolicy.class, new BooleanPolicy(BooleanOperator.AND,
                new StringAttribute("A"), new StringAttribute("B")));
    }
}
