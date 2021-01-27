package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.common.policies.BooleanPolicy;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class BooleanPolicyParams {

    public static StandaloneTestParams get() {
        return new StandaloneTestParams(
                BooleanPolicy.class, 
                new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, new StringAttribute("A"), 
                        new StringAttribute("B"))
        );
    }
}
