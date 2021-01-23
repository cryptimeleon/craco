package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.kdf.lhl.UniversalHashFamily;
import de.upb.crypto.craco.kdf.lhl.UniversalHashFunction;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.random.RandomGenerator;

import java.util.ArrayList;
import java.util.Collection;

public class HashBasedKDFParams {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        UniversalHashFamily universalHashFamily = new UniversalHashFamily(376, 128);
        UniversalHashFunction function = universalHashFamily.seedFunction(
                RandomGenerator.getRandomNumberOfBitlength(universalHashFamily.seedLength())
        );

        // Universal Hash Function based KDF
        HashBasedKeyDerivationFunction uhfKDF = new HashBasedKeyDerivationFunction(function);
        toReturn.add(new StandaloneTestParams(uhfKDF.getClass(), uhfKDF));

        // SHA-256-based KDF
        HashBasedKeyDerivationFunction shaBasedKDF = new HashBasedKeyDerivationFunction();
        toReturn.add(new StandaloneTestParams(shaBasedKDF.getClass(), shaBasedKDF));

        return toReturn;
    }
}
