package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.SetOfAttributes;
import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class SetOfAttributeParams {

    public static StandaloneTestParams get() {
        StringAttribute one = new StringAttribute("one");
        StringAttribute two = new StringAttribute("two");
        StringAttribute three = new StringAttribute("three");
        SetOfAttributes soa = new SetOfAttributes(one, two, three);
        return new StandaloneTestParams(SetOfAttributes.class, soa);
    }
}
