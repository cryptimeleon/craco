package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06PublicParameters;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06Setup;
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

public class ABEKPGPSW06Example {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private ABEKPGPSW06PublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /** Creates a setup class that provides the algorithm parameters*/
        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();

        /**
         * Generates algorithm parameters:
         * 80 = security level, 5 = the maximum number of attributes in a cipher text
         */
        setup.doKeyGen(80, 5, false, false);

        /** The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /** Generates the encryption scheme*/
        predicateEncryptionScheme = new ABEKPGPSW06(setup.getPublicParameters());
        /** The master secret is needed for the generation of a DecryptionKey*/
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /** Generate a policy for the decryption key (KeyIndex)*/
        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode =
                new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));
        /** Policy is ((A,B)'1 ,(B, C, D)'2)'2 := (A + B) * (CD + DE + CE)*/
        KeyIndex keyIndex = new ThresholdPolicy(2, leftNode, rightNode);
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);

        /** Generate a cipher text index for the encryption key*/
        CiphertextIndex ciphertextIndex =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("C"), new StringAttribute("D"));
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);
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
        ABEKPGPSW06Example kp = new ABEKPGPSW06Example();
        kp.setup();
        kp.generateKeys();
        kp.encryptDecrypt();
    }
}
