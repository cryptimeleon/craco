package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05;
import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05PublicParameters;
import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05Setup;
import de.upb.crypto.predenc.kem.fuzzy.large.IBEFuzzySW05KEM;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTest;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Parameters used in {@link StandaloneTest} for the Fuzzy IBE large universe family.
 */
public class IBEFuzzySW05Params {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        // setup Fuzzy environment with security parameter = 60, number of attributes = 6, threshold = 3
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);

        // add Fuzzy public parameters to test
        toReturn.add(new StandaloneTestParams(IBEFuzzySW05PublicParameters.class, setup.getPublicParameters()));

        // add Fuzzy IBE large universe construction to test
        IBEFuzzySW05 large = new IBEFuzzySW05(setup.getPublicParameters());
        toReturn.add(new StandaloneTestParams(IBEFuzzySW05.class, large));

        // add more efficient Fuzzy IBE KEM large universe construction to test
        IBEFuzzySW05KEM kem = new IBEFuzzySW05KEM(setup.getPublicParameters());
        toReturn.add(new StandaloneTestParams(kem));

        return toReturn;
    }
}
