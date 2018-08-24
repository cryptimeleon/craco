package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.SymmetricKey;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;
import de.upb.crypto.craco.kem.StreamingHybridEncryptionScheme;
import de.upb.crypto.craco.kem.SymmetricKeyPredicateKEM;
import de.upb.crypto.craco.kem.abe.cp.large.ABECPWat11KEM;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class CPLargeKEMHybridConstrution {

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
            /**
             * Use the symmetric key provided in KeyAndCipherText to encrypt the payload
             */
            StreamingHybridEncryptionScheme hybrid = new StreamingHybridEncryptionScheme(
                    new StreamingGCMAESPacketMode(), kem);
            byte[] randomPlaintext = "randomPlaintext".getBytes(StandardCharsets.UTF_8);

            /** Plain text input stream (can be any input stream) */
            InputStream plainIn = new ByteArrayInputStream(randomPlaintext);
            /** Cipher text output stream */
            OutputStream cipherOut = new BufferedOutputStream(new FileOutputStream(new File("ciphertext.ct")));
            /** the encapsulation happens in the encrypt */
            /**
             * reads all the bytes from the input stream, encrypts them and writes them into the output stream
             */
            hybrid.encrypt(plainIn, cipherOut, encryptionKey);
            plainIn.close();
            cipherOut.close();

            /** Ciphertext input stream */
            InputStream cipherIn = new BufferedInputStream(new FileInputStream(new File("ciphertext.ct")));
            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            /** decapsulation happens in the decrypt */
            hybrid.decrypt(cipherIn, plainOut, decryptionKey);

            cipherIn.close();
            assertTrue(Arrays.equals(randomPlaintext, plainOut.toByteArray()));
            plainOut.close();
            Files.deleteIfExists(new File("ciphertext.ct").toPath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
