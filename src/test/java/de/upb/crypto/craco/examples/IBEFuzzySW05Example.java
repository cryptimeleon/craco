package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05;
import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05PublicParameters;
import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05Setup;
import de.upb.crypto.craco.abe.fuzzy.large.Identity;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
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

public class IBEFuzzySW05Example {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private IBEFuzzySW05PublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /** Creates a setup class that provides the algorithm parameters */
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();

        /**
         * Generates algorithm parameters: 80 = security level, 6 = the maximum
         * number of attributes in a Identity, 3 the required number of
         * attributes in a the intersection
         */
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, false);

        /** The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /** Generates the encryption scheme */
        predicateEncryptionScheme = new IBEFuzzySW05(setup.getPublicParameters());
        /** The master secret is needed for the generation of a DecryptionKey */
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /** Create the Identity for the ciphertextIndex */
        Identity omega0 = new Identity();
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(1)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(2)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(5)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(6)));

        CiphertextIndex ciphertextIndex = (CiphertextIndex) omega0;
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);
        /** Create the Identity for the KeyIndex */
        Identity omega1 = new Identity();
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(7)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(9)));
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
        IBEFuzzySW05Example fuzzy = new IBEFuzzySW05Example();
        fuzzy.setup();
        fuzzy.generateKeys();
        fuzzy.encryptDecrypt();
    }
}
