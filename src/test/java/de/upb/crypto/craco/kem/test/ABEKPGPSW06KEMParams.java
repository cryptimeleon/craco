package de.upb.crypto.craco.kem.test;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06MasterSecret;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06PublicParameters;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06Setup;
import de.upb.crypto.craco.abe.util.ABEKPGPSW06TestParamsGenerator;
import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.kem.SymmetricKeyPredicateKEM;
import de.upb.crypto.predenc.kem.abe.kp.large.ABEKPGPSW06KEM;

import java.util.ArrayList;
import java.util.List;

public class ABEKPGPSW06KEMParams {
    public static ArrayList<KeyEncapsulationMechanismTestParams> getParams() {
        ArrayList<KeyEncapsulationMechanismTestParams> toReturn = new ArrayList<>();

        // setup KP environment with security parameter = 80, maximal number of attributes = 10
        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 10, false, true);

        ABEKPGPSW06MasterSecret msk = setup.getMasterSecret();
        ABEKPGPSW06PublicParameters publicParams = setup.getPublicParameters();
        ABEKPGPSW06KEM scheme = new ABEKPGPSW06KEM(publicParams);
        SymmetricKeyPredicateKEM symmetricKeyPredicateKEM = new SymmetricKeyPredicateKEM(scheme,
                new HashBasedKeyDerivationFunction());

        // test string attributes, test with 5 attributes
        Attribute[] stringAttr = ABEKPGPSW06TestParamsGenerator.generateStringAttributes();
        List<KeyPair> strKeyPairs = ABEKPGPSW06TestParamsGenerator.generateKeyPairs(scheme, msk, stringAttr);
        toReturn.add(new KeyEncapsulationMechanismTestParams(scheme, strKeyPairs.get(0), strKeyPairs.get(1)));
        // can reuse the keys generated for the underlying KEM scheme
        toReturn.add(new KeyEncapsulationMechanismTestParams(symmetricKeyPredicateKEM, strKeyPairs.get(0),
                strKeyPairs.get(1)));

        // test integer attributes, test with 5 attributes
        Attribute[] intAttr = ABEKPGPSW06TestParamsGenerator.generateIntegerAttributes();
        List<KeyPair> intKeyPairs = ABEKPGPSW06TestParamsGenerator.generateKeyPairs(scheme, msk, intAttr);
        toReturn.add(new KeyEncapsulationMechanismTestParams(scheme, intKeyPairs.get(0), intKeyPairs.get(1)));
        // can reuse the keys generated for the underlying KEM scheme
        toReturn.add(new KeyEncapsulationMechanismTestParams(symmetricKeyPredicateKEM, strKeyPairs.get(0),
                strKeyPairs.get(1)));

        return toReturn;
    }
}
