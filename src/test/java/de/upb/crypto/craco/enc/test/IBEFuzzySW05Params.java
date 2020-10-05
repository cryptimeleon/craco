package de.upb.crypto.craco.enc.test;

import de.upb.crypto.craco.abe.fuzzy.large.*;
import de.upb.crypto.craco.abe.util.IBEFuzzySW05TestParamGenerator;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;

import java.math.BigInteger;
import java.util.function.Supplier;

public class IBEFuzzySW05Params {

    public static TestParams getParams() {
        // setup Fuzzy environment with security parameter = 60, number of attributes = 6, threshold = 3
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);

        IBEFuzzySW05PublicParameters pp = setup.getPublicParameters();
        IBEFuzzySW05MasterSecret msk = setup.getMasterSecret();
        IBEFuzzySW05 fuzzy = new IBEFuzzySW05(pp);

        // generate identities for testing
        Identity omegaPubKey = IBEFuzzySW05TestParamGenerator.generatePublicKeyIdentity();
        Identity omegaValid = IBEFuzzySW05TestParamGenerator.generatePrivateKeyValidIdentity();
        Identity omegaCorrupted = IBEFuzzySW05TestParamGenerator.generatePrivateKeyCorruptedIdentity();

        // key generation based on the identities generated before
        EncryptionKey publicKey = fuzzy.generateEncryptionKey(omegaPubKey);
        DecryptionKey validSecretKey = fuzzy.generateDecryptionKey(msk, omegaValid);
        DecryptionKey corruptedSecretKey = fuzzy.generateDecryptionKey(msk, omegaCorrupted);

        Supplier<PlainText> supplier = () -> ((PlainText) new GroupElementPlainText(
                pp.getGroupGT().getUniformlyRandomElement()));

        KeyPair validKeyPair = new KeyPair(publicKey, validSecretKey);
        KeyPair corruptedKeyPair = new KeyPair(publicKey, corruptedSecretKey);

        return new TestParams(fuzzy, supplier, validKeyPair, corruptedKeyPair);
    }
}
