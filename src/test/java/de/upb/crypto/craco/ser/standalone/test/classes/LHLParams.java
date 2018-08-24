package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.kdf.lhl.InsufficientEntropyException;
import de.upb.crypto.craco.kdf.lhl.LHLFamily;
import de.upb.crypto.craco.kdf.lhl.LHLKeyDerivationFunction;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

public class LHLParams {

    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        try {
            LHLFamily fm = new LHLFamily(60, 376, 128, 376);
            toReturn.add(new StandaloneTestParams(fm));

            LHLKeyDerivationFunction fct = fm.seed();
            toReturn.add(new StandaloneTestParams(fct.getClass(), fct));
        } catch (InsufficientEntropyException e) {
            e.printStackTrace();
        }
        return toReturn;
    }
}
