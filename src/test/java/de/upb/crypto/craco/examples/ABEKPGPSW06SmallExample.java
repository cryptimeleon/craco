package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.kp.small.ABEKPGPSW06Small;
import de.upb.crypto.craco.abe.kp.small.ABEKPGPSW06SmallPublicParameters;
import de.upb.crypto.craco.abe.kp.small.ABEKPGPSW06SmallSetup;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import static org.junit.Assert.assertTrue;

public class ABEKPGPSW06SmallExample {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private ABEKPGPSW06SmallPublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /** Creates a setup class that provides the algorithm parameters */
        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();

        /**
         * Creates the universe of attributes. THe KeyIndex/CipherTextIndex can
         * only use attributes out of this universe
         */
        SetOfAttributes universe = new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"),
                new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));
        /**
         * Generates algorithm parameters: 80 = security level, universe
         * specifies the attributes that can be used in the key and cipher text
         */
        setup.doKeyGen(80, universe, false);

        /** The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /** Generates the encryption scheme */
        predicateEncryptionScheme = new ABEKPGPSW06Small(setup.getPublicParameters());
        /** The master secret is needed for the generation of a DecryptionKey */
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /** Generate a policy for the decryption key (KeyIndex) */
        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode = new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"),
                new StringAttribute("E"));
        /** Policy is ((A,B)'1 ,(B, C, D)'2)'2 := (A + B) * (CD + DE + CE) */
        KeyIndex keyIndex = new ThresholdPolicy(2, leftNode, rightNode);
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);

        /** Generate a cipher text index for the encryption key */
        CiphertextIndex ciphertextIndex = new SetOfAttributes(new StringAttribute("A"), new StringAttribute("C"),
                new StringAttribute("D"));
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);
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
        ABEKPGPSW06SmallExample kp = new ABEKPGPSW06SmallExample();
        kp.setup();
        kp.generateKeys();
        kp.encryptDecrypt();
    }
}
