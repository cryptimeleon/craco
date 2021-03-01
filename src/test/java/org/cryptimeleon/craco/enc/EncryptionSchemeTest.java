package org.cryptimeleon.craco.enc;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.params.ElgamalParams;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

import static org.junit.Assert.*;

@RunWith(value = Parameterized.class)
public class EncryptionSchemeTest {

    private Supplier<PlainText> plaintextSupplier;

    private EncryptionScheme encryptionScheme;

    private EncryptionKeyPair validKeyPair;

    private EncryptionKeyPair invalidKeyPair;

    public EncryptionSchemeTest(TestParams params) {
        this.encryptionScheme = params.encryptionScheme;
        this.plaintextSupplier = params.plainTextSupplier;
        this.validKeyPair = params.validKeyPair;
        this.invalidKeyPair = params.invalidKeyPair;
    }

    @Test
    public void testEncryptDecrypt() throws UnsupportedEncodingException {
        System.out.println("Testing valid encrypt/decrypt for " + encryptionScheme.getClass().getName() + " ...");
        PlainText data = plaintextSupplier.get();

        DecryptionKey sk = validKeyPair.getSk();
        EncryptionKey pk = validKeyPair.getPk();

        // Do an encryption/decryption run
        CipherText cipherText = encryptionScheme.encrypt(data, pk);
        PlainText decryptedCipherText = encryptionScheme.decrypt(cipherText, sk);
        assertEquals(data, decryptedCipherText);
    }

    @Test
    public void testFailEncryptDecrypt() throws UnsupportedEncodingException {
        System.out.println("Testing invalid encrypt/decrypt for " + encryptionScheme.getClass().getName() + " ...");

        PlainText data = plaintextSupplier.get();

        DecryptionKey sk = invalidKeyPair.getSk();
        EncryptionKey pk = invalidKeyPair.getPk();

        // Do a encryption/decryption run
        CipherText cipherText = encryptionScheme.encrypt(data, pk);
        try {
            PlainText decryptedCipherText = encryptionScheme.decrypt(cipherText, sk);
            assertNotEquals(data, decryptedCipherText);
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException); //schemes should throw IllegalArgumentException if the
            // key is not fit to decrypt.
        }
    }

    @Parameters(name = "{index}: {0}")
    public static Collection<TestParams> data() {
        ArrayList<TestParams> schemes = new ArrayList<>();
        //non generic schemes
        schemes.add(ElgamalParams.getParams());
        return schemes;
    }

}
