package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class SetOfAttributeParams {

    public static StandaloneTestParams get() {
        StringAttribute one = new StringAttribute("one");
        StringAttribute two = new StringAttribute("two");
        StringAttribute three = new StringAttribute("three");
        SetOfAttributes soa = new SetOfAttributes(one, two, three);
        return new StandaloneTestParams(SetOfAttributes.class, soa);
    }
}
