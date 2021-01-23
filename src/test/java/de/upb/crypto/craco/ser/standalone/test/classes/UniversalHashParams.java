package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.kdf.lhl.UniversalHashFamily;
import de.upb.crypto.craco.kdf.lhl.UniversalHashFunction;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.random.RandomGenerator;

import java.util.ArrayList;
import java.util.Collection;

public class UniversalHashParams {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        UniversalHashFamily universalHashFamily = new UniversalHashFamily(376, 128);
        toReturn.add(new StandaloneTestParams(universalHashFamily.getClass(), universalHashFamily));

        UniversalHashFunction function = universalHashFamily.seedFunction(
                RandomGenerator.getRandomNumberOfBitlength(universalHashFamily.seedLength())
        );
        toReturn.add(new StandaloneTestParams(function.getClass(), function));

        return toReturn;
    }
}
