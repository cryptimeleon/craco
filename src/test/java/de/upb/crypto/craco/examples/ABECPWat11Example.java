package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.common.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import static org.junit.Assert.assertTrue;

public class ABECPWat11Example {

    private PredicateEncryptionScheme predicateEncryptionScheme;

    private ABECPWat11PublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /** Creates a setup class that provides the algorithm parameters*/
        ABECPWat11Setup setup = new ABECPWat11Setup();

        /**
         * Generates algorithm parameters:
         * 80 = security level, 5 = the maximum number of attributes in a key, 5 = maximum number of leaf-node
         * attributes in a policy
         */
        setup.doKeyGen(80, 5, 5, false, false);

        /** The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /** Generates the encryption scheme*/
        predicateEncryptionScheme = new ABECPWat11(setup.getPublicParameters());
        /** The master secret is needed for the generation of a DecryptioKey*/
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /** Generate a policy for the encryption key (CipherTextIndex)*/
        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode =
                new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));
        /** Policy is ((A,B)'1 ,(B, C, D)'2)'2 := (A + B) * (CD + DE + CE)*/
        CiphertextIndex ciphertextIndex = new ThresholdPolicy(2, leftNode, rightNode);
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);

        /** Generate a KeyIndex for the decryption key*/
        KeyIndex keyIndex =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("C"), new StringAttribute("D"));
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);
    }

    public void encryptDecrypt() {
        /** Encrypt a random element*/
        GroupElement randomElement = publicParameters.getGroupGT().getUniformlyRandomElement();
        PlainText plainText = new GroupElementPlainText(randomElement);
        /** Encrypt it*/
        CipherText cipherText = predicateEncryptionScheme.encrypt(plainText, encryptionKey);
        /** Decrypt it again*/
        PlainText decryptedPlainText = predicateEncryptionScheme.decrypt(cipherText, decryptionKey);
        assertTrue(plainText.equals(decryptedPlainText));
    }

    public static void main(String[] args) {
        ABECPWat11Example cp = new ABECPWat11Example();
        cp.setup();
        cp.generateKeys();
        cp.encryptDecrypt();
    }
}
