package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.policies.BooleanPolicy;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class BooleanPolicyParams {

    public static StandaloneTestParams get() {
        return new StandaloneTestParams(
                BooleanPolicy.class, 
                new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, new StringAttribute("A"), 
                        new StringAttribute("B"))
        );
    }
}
