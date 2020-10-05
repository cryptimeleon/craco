package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.SymmetricKey;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.common.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism.KeyAndCiphertext;
import de.upb.crypto.craco.kem.SymmetricKeyPredicateKEM;
import de.upb.crypto.craco.kem.abe.cp.large.ABECPWat11KEM;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.assertTrue;

public class CPLargeKEMConstruction {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private KeyEncapsulationMechanism<SymmetricKey> kem;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public static void main(String[] args) {
        CPLargeKEMConstruction cp = new CPLargeKEMConstruction();
        cp.setup();
        cp.generateKeys();
        cp.encryptDecrypt();
    }

    public void setup() {
        /** Creates a setup class that provides the algorithm parameters */
        ABECPWat11Setup setup = new ABECPWat11Setup();

        /**
         * Generates algorithm parameters: 80 = security level, 5 = the maximum number of attributes in a key, 5 =
         * maximum number of leaf-node attributes in a policy
         */
        setup.doKeyGen(80, 5, 5, false, false);

        /** Generates the encryption scheme */
        predicateEncryptionScheme = new ABECPWat11(setup.getPublicParameters());
        /** The master secret is needed for the generation of a DecryptioKey */
        masterSecret = setup.getMasterSecret();
        kem = new SymmetricKeyPredicateKEM(new ABECPWat11KEM(setup.getPublicParameters()),
                new HashBasedKeyDerivationFunction());
    }

    public void generateKeys() {
        /** Generate a policy for the encryption key (CipherTextIndex) */
        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode = new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"),
                new StringAttribute("E"));
        /** Policy is ((A,B)'1 ,(B, C, D)'2)'2 := (A + B) * (CD + DE + CE) */
        CiphertextIndex ciphertextIndex = new ThresholdPolicy(2, leftNode, rightNode);
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);

        /** Generate a KeyIndex for the decryption key */
        KeyIndex keyIndex = new SetOfAttributes(new StringAttribute("A"), new StringAttribute("C"),
                new StringAttribute("D"));
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);
    }

    public void encryptDecrypt() {
        try {
            /** Encapsulate a key */
            KeyAndCiphertext<SymmetricKey> kac = kem.encaps(encryptionKey);
            /**
             * Use the symmetric key provided in KeyAndCipherText to encrypt the payload
             */
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            /** Set up an AES scheme */
            SecretKeySpec keySpec = new SecretKeySpec(((ByteArrayImplementation) kac.key).getData(), "AES");
            /** CBC initial vector */
            byte[] initialVector = new byte[128 / 8];
            new Random().nextBytes(initialVector);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(initialVector));
            byte[] plainText = "randomPlainText".getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = cipher.doFinal(plainText);

            /**
             * Transmit the KeyAndCipherText, the inital vector and the cipher text
             */

            /** Decryption */
            /** Get the encapsulated symmetric key */
            SymmetricKey symmetricKey = kem.decaps(kac.encapsulatedKey, decryptionKey);
            keySpec = new SecretKeySpec(((ByteArrayImplementation) symmetricKey).getData(), "AES");
            /** set up an aes scheme */
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(initialVector));
            /** decryption */
            byte[] decryptedCipertext = cipher.doFinal(ciphertext);

            assertTrue(Arrays.equals(plainText, decryptedCipertext));

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
