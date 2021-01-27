package de.upb.crypto.craco.enc.streaming;

import de.upb.crypto.craco.common.utils.StreamUtil;
import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.enc.StreamingEncryptionScheme;
import de.upb.crypto.craco.enc.streaming.params.StreamingAESParams;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(value = Parameterized.class)
public class StreamingEncryptionSchemeTest {

    private static SecureRandom RANDOM = new SecureRandom();

    private static int LENGTH = 18 * 1024;

    private static String PATH = "src/test/java/de/upb/crypto/craco/enc/streaming/";

    private static String CIPHERTEXT_PATH = PATH + "cipherText";

    private StreamingEncryptionScheme encryptionScheme;

    private KeyPair keyPair;

    public StreamingEncryptionSchemeTest(StreamingEncryptionSchemeParams params) {
        this.encryptionScheme = params.getEncryptionScheme();
        this.keyPair = params.getKeyPair();
    }

    @Test
    public void testDeprecatedStreamingEncryptDecrypt() {
        try {
            System.out
                    .println("Testing the encrypt(InputStream plainIn, OutputStream cipherOut, EncryptionKey pk) for "
                            + encryptionScheme.getClass().getName());
            // Generate new random bytes to be decrypted
            byte[] randomBytes = new byte[LENGTH];
            RANDOM.nextBytes(randomBytes);
            // create a buffered input stream that reads the bytes
            ByteArrayInputStream plainBytesIn = new ByteArrayInputStream(randomBytes);
            InputStream plainIn = new BufferedInputStream(plainBytesIn);
            // its more comfortable to write it into a text file
            OutputStream cipherOut = new BufferedOutputStream(new FileOutputStream(new File(CIPHERTEXT_PATH)));
            // encrypt it into the file
            encryptionScheme.encrypt(plainIn, cipherOut, keyPair.getPk());
            plainIn.close();
            cipherOut.close();
            System.out
                    .println("Testing the decrypt(InputStream cipherIn, OutputStream plainOut, DecryptionKey sk) for "
                            + encryptionScheme.getClass().getName());

            // create a input stream from the file
            InputStream cipherIn = new BufferedInputStream(new FileInputStream(new File(CIPHERTEXT_PATH)));
            // write it back into a byte array
            ByteArrayOutputStream plainBytesOut = new ByteArrayOutputStream();
            OutputStream plainOut = new BufferedOutputStream(plainBytesOut);
            // decrypt it
            encryptionScheme.decrypt(cipherIn, plainOut, keyPair.getSk());
            plainOut.flush();
            System.out.println("Asserting the results...");
            assertTrue(Arrays.equals(plainBytesOut.toByteArray(), randomBytes));
            // cleanup
            cipherIn.close();
            plainOut.close();

        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testEncryptInputStreamAndDecryptInputStream() {
        try {
            System.out.println("Testing the encrypt(InputStream plainIn, EncryptionKey pk) for "
                    + encryptionScheme.getClass().getName());

            // Generate new random bytes to be decrypted
            byte[] randomBytes = new byte[LENGTH];
            RANDOM.nextBytes(randomBytes);
            // create a buffered input stream that reads the bytes
            ByteArrayInputStream plainBytesIn = new ByteArrayInputStream(randomBytes);
            // read the encrypted bytes only
            InputStream encryptedInputStream = encryptionScheme.encrypt(plainBytesIn, keyPair.getPk());
            FileOutputStream fos = new FileOutputStream(new File(CIPHERTEXT_PATH));
            StreamUtil.copy(encryptedInputStream, fos);
            fos.flush();
            fos.close();
            FileInputStream fis = new FileInputStream(new File(CIPHERTEXT_PATH));
            ByteArrayOutputStream plainBytesOut = new ByteArrayOutputStream(LENGTH);
            System.out.println("Testing the decrypt(InputStream cipherIn, DecryptionKey sk) for "
                    + encryptionScheme.getClass().getName());

            InputStream decryptedCiphertext = encryptionScheme.decrypt(fis, keyPair.getSk());

            StreamUtil.copy(decryptedCiphertext, plainBytesOut);
            plainBytesOut.flush();
            encryptedInputStream.close();
            plainBytesOut.close();
            decryptedCiphertext.close();
            System.out.println("Asserting the results...");
            assertTrue(Arrays.equals(plainBytesOut.toByteArray(), randomBytes));
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testEncryptOutputStreamAndDecryptOutputStream() {
        try {
            System.out.println("Testing the encrypt(OutputStream cipherOut, EncryptionKey pk) for "
                    + encryptionScheme.getClass().getName());
            // Generate new random bytes to be decrypted
            byte[] randomBytes = new byte[LENGTH];
            RANDOM.nextBytes(randomBytes);
            // create a buffered input stream that reads the bytes
            ByteArrayInputStream plainBytesIn = new ByteArrayInputStream(randomBytes);
            InputStream plainIn = new BufferedInputStream(plainBytesIn);
            // write them into a file
            OutputStream plainOut = new BufferedOutputStream(new FileOutputStream(new File(CIPHERTEXT_PATH)));
            // output the encrypted bytes
            OutputStream encryptedOutputStream = encryptionScheme.encrypt(plainOut, keyPair.getPk());
            StreamUtil.copy(plainIn, encryptedOutputStream);
            // cleanup

            plainIn.close();
            encryptedOutputStream.close();
            System.out.println("Testing the decrypt(OutputStream plainOut, DecryptionKey sk) for "
                    + encryptionScheme.getClass().getName());

            // -----------------Decryption-----------------

            // create an input stream from the file
            InputStream cipherIn = new BufferedInputStream(new FileInputStream(new File(CIPHERTEXT_PATH)));
            // write it back into a byte array
            ByteArrayOutputStream cipherBytesOut = new ByteArrayOutputStream();
            OutputStream cipherOut = new BufferedOutputStream(cipherBytesOut);
            OutputStream decryptedCipherOut = encryptionScheme.decrypt(cipherOut, keyPair.getSk());
            StreamUtil.copy(cipherIn, decryptedCipherOut);
            cipherIn.close();

            decryptedCipherOut.close();
            System.out.println("Asserting the results...");

            assertTrue(Arrays.equals(cipherBytesOut.toByteArray(), randomBytes));

        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }

    @AfterClass
    public static void cleanup() {
        try {
            Files.delete(new File(CIPHERTEXT_PATH).toPath());
        } catch (IOException e) {
        }
    }

    @Parameters(name = "{index}: {0}")
    public static Collection<StreamingEncryptionSchemeParams> data() {
        ArrayList<StreamingEncryptionSchemeParams> toReturn = new ArrayList<>();
        toReturn.addAll(Arrays.asList(StreamingAESParams.getParams()));
        return toReturn;
    }
}

