package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class SetOfAttributeParams {

    public static StandaloneTestParams get() {
        StringAttribute one = new StringAttribute("one");
        StringAttribute two = new StringAttribute("two");
        StringAttribute three = new StringAttribute("three");
        SetOfAttributes soa = new SetOfAttributes(one, two, three);
        return new StandaloneTestParams(SetOfAttributes.class, soa);
    }
}
