package de.upb.crypto.craco.kem.test;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11MasterSecret;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.abe.util.ABECPWat11TestParamGenerator;
import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.predenc.kem.abe.cp.large.ABECPWat11KEM;

import java.util.ArrayList;
import java.util.List;

/**
 * Parameters for {@link ABECPWat11KEM} and instantiation of it with {@link SymmetricKeyPredicateKEM} used in
 * {@link KeyEncapsulationMechanismTest}.
 */
public class ABECPWat11KEMParams {
    public static ArrayList<KeyEncapsulationMechanismTestParams> getParams() {
        ABECPWat11Setup setup = new ABECPWat11Setup();
        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number of attributes in the MSP)
        setup.doKeyGen(80, 5, 5, false, true);
        ABECPWat11PublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11MasterSecret msk = setup.getMasterSecret();

        // KEM outputting KeyMaterial
        ABECPWat11KEM kemScheme = new ABECPWat11KEM(publicParams);

        // KEM outputting SymmetricKey
        HashBasedKeyDerivationFunction hashBasedKDF = new HashBasedKeyDerivationFunction();
        SymmetricKeyPredicateKEM kemSchemeHBKDF = new SymmetricKeyPredicateKEM(kemScheme, hashBasedKDF);

        // string attributes parameters
        List<KeyPair> stringAttrKeys = ABECPWat11TestParamGenerator.generateLargeUniverseTestKeys(msk, kemScheme,
                ABECPWat11TestParamGenerator.generateStringAttributesToTest());
        KeyEncapsulationMechanismTestParams stringAttrParams = new KeyEncapsulationMechanismTestParams(kemScheme,
                stringAttrKeys.get(0), stringAttrKeys.get(1));
        // we can reuse the keys generated for kemScheme, since SymmetricKeyPredicateKEM is just a wrapper and uses the
        // same method internally
        KeyEncapsulationMechanismTestParams stringAttrParamsHBKDF = new KeyEncapsulationMechanismTestParams(
                kemSchemeHBKDF, stringAttrKeys.get(0), stringAttrKeys.get(1));

        // integer attributes parameters
        List<KeyPair> integerAttrKeys = ABECPWat11TestParamGenerator.generateLargeUniverseTestKeys(msk, kemScheme,
                ABECPWat11TestParamGenerator.generateIntegerAttributesToTest());
        KeyEncapsulationMechanismTestParams integerAttrParams = new KeyEncapsulationMechanismTestParams(kemScheme,
                integerAttrKeys.get(0), integerAttrKeys.get(1));
        // we can reuse the keys generated for kemScheme, since SymmetricKeyPredicateKEM is just a wrapper and uses the
        // same method internally
        KeyEncapsulationMechanismTestParams integerAttrParamsHBKDF = new KeyEncapsulationMechanismTestParams(
                kemSchemeHBKDF, integerAttrKeys.get(0), integerAttrKeys.get(1));

        ArrayList<KeyEncapsulationMechanismTestParams> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        toReturn.add(stringAttrParamsHBKDF);
        toReturn.add(integerAttrParamsHBKDF);

        return toReturn;
    }
}
