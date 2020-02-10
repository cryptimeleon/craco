package de.upb.crypto.craco.examples;

import de.upb.crypto.craco.abe.ibe.FullIdent;
import de.upb.crypto.craco.abe.ibe.FullIdentSetup;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.common.interfaces.pe.PredicateEncryptionScheme;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.Assert.assertTrue;

public class FullIdentConstruction {

    private PredicateEncryptionScheme predicateEncryptionScheme;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /** Creates a setup class that provides the algorithm parameters */
        FullIdentSetup setup = new FullIdentSetup();

        /**
         * Generates algorithm parameters: 80 = security level, 10 = the
         * universe (meaning the the numbers 1 to 10 are in the universe), = 3
         * the required number of attributes in a the intersection
         */
        setup.doKeyGen(80, BigInteger.valueOf(1024), false);

        /** Generates the encryption scheme */
        predicateEncryptionScheme = new FullIdent(setup.getPublicParameters());
        /** The master secret is needed for the generation of a DecryptionKey */
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /** Create the ciphertextIndex */
        byte[] identity = "randomString".getBytes(StandardCharsets.UTF_8);

        CiphertextIndex ciphertextIndex = new ByteArrayImplementation(identity);

        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);

        KeyIndex keyIndex = new ByteArrayImplementation(identity);
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);

    }

    public void encryptDecrypt() {
        /** Encrypt a random element */
        byte[] randomElement = new byte[1024];
        new Random().nextBytes(randomElement);
        PlainText plainText = new ByteArrayImplementation(randomElement);
        /** Encrypt it */
        CipherText cipherText = predicateEncryptionScheme.encrypt(plainText, encryptionKey);
        /** Decrypt it again */
        PlainText decryptedPlainText = predicateEncryptionScheme.decrypt(cipherText, decryptionKey);
        assertTrue(plainText.equals(decryptedPlainText));
    }

    public static void main(String[] args) {
        FullIdentConstruction fullIdent = new FullIdentConstruction();
        fullIdent.setup();
        fullIdent.generateKeys();
        fullIdent.encryptDecrypt();
    }
}
