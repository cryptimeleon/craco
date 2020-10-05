package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.fuzzy.small.IBEFuzzySW05Small;
import de.upb.crypto.craco.abe.fuzzy.small.IBEFuzzySW05SmallPublicParameters;
import de.upb.crypto.craco.abe.fuzzy.small.IBEFuzzySW05SmallSetup;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.common.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.math.BigInteger;

import static org.junit.Assert.assertTrue;

public class IBEFuzzySW05SmallExample {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private IBEFuzzySW05SmallPublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /** Creates a setup class that provides the algorithm parameters */
        IBEFuzzySW05SmallSetup setup = new IBEFuzzySW05SmallSetup();

        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 10; i++) {
            universe.add(new BigIntegerAttribute(i));
        }

        /**
         * Generates algorithm parameters: 80 = security level, 10 = the
         * universe (meaning the the numbers 1 to 10 are in the universe), = 3
         * the required number of attributes in a the intersection
         */
        setup.doKeyGen(80, universe, BigInteger.valueOf(3), false);

        /** The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /** Generates the encryption scheme */
        predicateEncryptionScheme = new IBEFuzzySW05Small(setup.getPublicParameters());
        /** The master secret is needed for the generation of a DecryptionKey */
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /** Create the Identity for the ciphertextIndex */
        SetOfAttributes omega0 = new SetOfAttributes();
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(1)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(2)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(5)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(6)));

        CiphertextIndex ciphertextIndex = (CiphertextIndex) omega0;
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);
        /** Create the Identity for the KeyIndex */
        SetOfAttributes omega1 = new SetOfAttributes();
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(7)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(9)));
        KeyIndex keyIndex = (KeyIndex) omega1;
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);

    }

    public void encryptDecrypt() {
        /** Encrypt a random element */
        GroupElement randomElement = publicParameters.getGroupGT().getUniformlyRandomElement();
        PlainText plainText = new GroupElementPlainText(randomElement);
        /** Encrypt it */
        CipherText cipherText = predicateEncryptionScheme.encrypt(plainText, encryptionKey);
        /** Decrypt it again */
        PlainText decryptedPlainText = predicateEncryptionScheme.decrypt(cipherText, decryptionKey);
        assertTrue(plainText.equals(decryptedPlainText));
    }

    public static void main(String[] args) {
        IBEFuzzySW05SmallExample fuzzy = new IBEFuzzySW05SmallExample();
        fuzzy.setup();
        fuzzy.generateKeys();
        fuzzy.encryptDecrypt();
    }
}
