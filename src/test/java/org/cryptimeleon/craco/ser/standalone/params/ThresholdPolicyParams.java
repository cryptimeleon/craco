package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class ThresholdPolicyParams {
    public static StandaloneTestParams get() {
        Attribute[] attributes = {
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        };
        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);
        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);
        return new StandaloneTestParams(ThresholdPolicy.class, new ThresholdPolicy(2, leftNode, rightNode));
    }
}
