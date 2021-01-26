package de.upb.crypto.craco.kem.test;

import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05MasterSecret;
import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05PublicParameters;
import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05Setup;
import de.upb.crypto.craco.abe.fuzzy.large.Identity;
import de.upb.crypto.craco.abe.util.IBEFuzzySW05TestParamGenerator;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.kem.SymmetricKeyPredicateKEM;
import de.upb.crypto.predenc.kem.fuzzy.large.IBEFuzzySW05KEM;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Parameters used in {@link KeyEncapsulationMechanismTest} for the {@link IBEFuzzySW05KEM} and its symmetric variant.
 */
public class IBEFuzzySW05KEMParams {
    public static List<KeyEncapsulationMechanismTestParams> getParams() {
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);
        IBEFuzzySW05PublicParameters pp = setup.getPublicParameters();
        IBEFuzzySW05MasterSecret msk = setup.getMasterSecret();

        IBEFuzzySW05KEM fuzzy = new IBEFuzzySW05KEM(pp);
        SymmetricKeyPredicateKEM fuzzySymmetricKey = new SymmetricKeyPredicateKEM(fuzzy,
                new HashBasedKeyDerivationFunction());

        Identity omegaPubKey = IBEFuzzySW05TestParamGenerator.generatePublicKeyIdentity();
        Identity omegaValid = IBEFuzzySW05TestParamGenerator.generatePrivateKeyValidIdentity();
        Identity omegaCorrupted = IBEFuzzySW05TestParamGenerator.generatePrivateKeyCorruptedIdentity();

        // we can reuse the keys generated for kemScheme, since SymmetricKeyPredicateKEM is just a wrapper and uses the
        // same method internally
        EncryptionKey publicKey = fuzzy.generateEncryptionKey(omegaPubKey);
        DecryptionKey validSecretKey = fuzzy.generateDecryptionKey(msk, omegaValid);
        DecryptionKey corruptedSecretKey = fuzzy.generateDecryptionKey(msk, omegaCorrupted);

        KeyPair validKeyPair = new KeyPair(publicKey, validSecretKey);
        KeyPair corruptedKeyPair = new KeyPair(publicKey, corruptedSecretKey);

        List<KeyEncapsulationMechanismTestParams> toReturn = new ArrayList<>();
        toReturn.add(new KeyEncapsulationMechanismTestParams(fuzzy, validKeyPair, corruptedKeyPair));
        toReturn.add(new KeyEncapsulationMechanismTestParams(fuzzySymmetricKey, validKeyPair, corruptedKeyPair));

        return toReturn;
    }
}
