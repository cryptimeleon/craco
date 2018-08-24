package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.kdf.uextr.UnpredictabilityKeyDerivationFamily;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

import java.util.ArrayList;
import java.util.List;

public class UExtractorParams {

    public static List<StandaloneTestParams> get() {
        List<StandaloneTestParams> toReturn = new ArrayList<StandaloneTestParams>();
        UnpredictabilityKeyDerivationFamily kdfFamily = new UnpredictabilityKeyDerivationFamily(20, 400, 256);

        toReturn.add(new StandaloneTestParams(kdfFamily));
        toReturn.add(new StandaloneTestParams(kdfFamily.seed()));

        return toReturn;
    }
}
