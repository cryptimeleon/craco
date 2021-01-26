package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06PublicParameters;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06Setup;
import de.upb.crypto.predenc.kem.abe.kp.large.ABEKPGPSW06KEM;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTest;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Parameters used in {@link StandaloneTest} for the KP-ABE large universe family.
 */
public class ABEKPGPSW06Params {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        // setup KP-ABE environment with security parameter = 60, number of attributes = 5
        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 5, false, true);

        // add KP public de.upb.crypto.groupsig.params to test
        ABEKPGPSW06PublicParameters kpp = setup.getPublicParameters();
        toReturn.add(new StandaloneTestParams(ABEKPGPSW06PublicParameters.class, kpp));

        // add KP-ABE large universe construction to test
        ABEKPGPSW06 scheme = new ABEKPGPSW06(kpp);
        toReturn.add(new StandaloneTestParams(ABEKPGPSW06.class, scheme));

        // add more efficient KP-ABE KEM large universe construction to test
        ABEKPGPSW06KEM kem = new ABEKPGPSW06KEM(kpp);
        toReturn.add(new StandaloneTestParams(kem));

        return toReturn;
    }
}
