package de.upb.crypto.craco.enc.test;

import de.upb.crypto.craco.common.interfaces.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(value = Parameterized.class)
public class EncryptionSchemeTest {

    private Supplier<PlainText> plaintextSupplier;

    private EncryptionScheme encryptionScheme;

    private KeyPair validKeyPair;

    private KeyPair invalidKeyPair;

    public EncryptionSchemeTest(TestParams params) {
        this.encryptionScheme = params.encryptionScheme;
        this.plaintextSupplier = params.plainTextSupplier;
        this.validKeyPair = params.validKeyPair;
        this.invalidKeyPair = params.invalidKeyPair;
    }

    @Test
    public void testEncryptDecrypt() throws UnsupportedEncodingException {
        System.out.println("Testing valid encrypt/decrypt for " + encryptionScheme.getRepresentedTypeName() + " ...");
        PlainText data = plaintextSupplier.get();

        DecryptionKey sk = validKeyPair.getSk();
        EncryptionKey pk = validKeyPair.getPk();

        // Do an encryption/decryption run
        CipherText cipherText = encryptionScheme.encrypt(data, pk);
        PlainText decryptedCipherText = encryptionScheme.decrypt(cipherText, sk);
        assertTrue(data.equals(decryptedCipherText));
    }

    @Test
    public void testFailEncryptDecrypt() throws UnsupportedEncodingException {
        System.out.println("Testing invalid encrypt/decrypt for " + encryptionScheme.getRepresentedTypeName() + " ...");

        PlainText data = plaintextSupplier.get();

        DecryptionKey sk = invalidKeyPair.getSk();
        EncryptionKey pk = invalidKeyPair.getPk();

        // Do a encryption/decryption run
        CipherText cipherText = encryptionScheme.encrypt(data, pk);
        try {
            PlainText decryptedCipherText = encryptionScheme.decrypt(cipherText, sk);
            assertFalse(data.equals(decryptedCipherText));
        } catch (Exception e) {
            assertTrue(e instanceof UnqualifiedKeyException); //schemes should throw UnqualifiedKeyExceptions if the
            // key is not fit to decrypt.
        }
    }

    @Parameters(name = "{index}: {0}")
    public static Collection<TestParams> data() {
        ArrayList<TestParams> schemes = new ArrayList<>();
        //non generic schemes
        schemes.add(ElgamalParams.getParams());
        schemes.add(IBEFuzzySW05SmallParams.getParams());
        schemes.add(IBEFuzzySW05Params.getParams());
        schemes.add(FullIdentParams.getParams());
        //generic schemes
        schemes.addAll(ABECPWat11Params.getParams());
        schemes.addAll(ABECPWat11SmallParams.getParams());
        schemes.addAll(ABEKPGPSW06Params.getParams());
        schemes.addAll(DistributedABECPWat11Params.getParams());
        return schemes;
    }

}
