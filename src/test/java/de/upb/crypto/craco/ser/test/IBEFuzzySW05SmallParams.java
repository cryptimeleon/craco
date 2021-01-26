package de.upb.crypto.craco.ser.test;

import de.upb.crypto.craco.abe.fuzzy.small.IBEFuzzySW05Small;
import de.upb.crypto.craco.abe.fuzzy.small.IBEFuzzySW05SmallMasterSecret;
import de.upb.crypto.craco.abe.fuzzy.small.IBEFuzzySW05SmallPublicParameters;
import de.upb.crypto.craco.abe.fuzzy.small.IBEFuzzySW05SmallSetup;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.common.PlainText;

import java.math.BigInteger;

public class IBEFuzzySW05SmallParams {

    public static RepresentationTestParams getParams() {

        IBEFuzzySW05SmallSetup setup = new IBEFuzzySW05SmallSetup();
        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 30; i++) {
            universe.add(new BigIntegerAttribute(i));
        }
        setup.doKeyGen(80, universe, BigInteger.valueOf(3), true);

        IBEFuzzySW05SmallPublicParameters pp = setup.getPublicParameters();

        IBEFuzzySW05SmallMasterSecret msk = setup.getMasterSecret();

        IBEFuzzySW05Small fuzzy = new IBEFuzzySW05Small(pp);

        SetOfAttributes omega0 = new SetOfAttributes();
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(1)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(2)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(5)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(20)));

        SetOfAttributes omega1 = new SetOfAttributes();
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(7)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(9)));

        EncryptionKey publicKey = fuzzy.generateEncryptionKey(omega0);
        DecryptionKey validSecretKey = fuzzy.generateDecryptionKey(msk, omega1);

        PlainText plaintext = new GroupElementPlainText(pp.getGroupGT().getUniformlyRandomElement());

        CipherText ciphertext = fuzzy.encrypt(plaintext, publicKey);

        return new RepresentationTestParams(fuzzy, publicKey, validSecretKey, plaintext, ciphertext, msk);
    }
}
