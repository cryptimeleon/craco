package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.kdf.uextr.KWiseDeltaDependentHashFamily;
import de.upb.crypto.craco.kdf.uextr.KWiseDeltaDependentHashFunction;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.structures.polynomial.Seed;

import java.util.ArrayList;
import java.util.Collection;

public class KWiseHashParams {

    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        KWiseDeltaDependentHashFamily family = new KWiseDeltaDependentHashFamily(9.0, -4608.0, 3072, 36);
        toReturn.add(new StandaloneTestParams(family.getClass(), family));
        KWiseDeltaDependentHashFunction function = family.seedFunction(new Seed(family.seedLength()));
        toReturn.add(new StandaloneTestParams(function.getClass(), function));

        return toReturn;
    }
}
