package de.upb.crypto.craco.kdf.test;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAES;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.KeyPair;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.kdf.lhl.LHLFamily;
import de.upb.crypto.craco.kdf.lhl.LHLKeyDerivationFunction;
import de.upb.crypto.craco.kem.StreamingHybridEncryptionScheme;
import de.upb.crypto.craco.kem.SymmetricKeyPredicateKEM;
import de.upb.crypto.craco.kem.abe.cp.large.ABECPWat11KEM;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class LHLKDFTest {
    private static final String PT_PATH = "src/test/resources/plain.txt";

    private static final String CT_PATH = "src/test/resources/cipher.txt";

    private static final String TEMP_PT_PATH = "src/test/resources/plain_temp.txt";

    @Test
    public void testCPLargeKeyDerivation() {
        System.out.println("Setting up CP large KEM");
        ABECPWat11Setup setup = new ABECPWat11Setup();
        setup.doKeyGen(1000, 5, 5, false, true);
        try {
            LHLKeyDerivationFunction kdf = new LHLFamily(60,
                    setup.getPublicParameters().getGroupGT().getUniqueByteLength()
                            .orElseThrow(() -> new RuntimeException("Cannot do key derivation if group ubr is not fixed")) * 8, 128,
                    setup.getPublicParameters().getGroupGT().size().bitLength()).seed();
            SymmetricKeyPredicateKEM kem = new SymmetricKeyPredicateKEM(
                    new ABECPWat11KEM(setup.getPublicParameters()), kdf);

            Attribute[] attributes = {new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                    new StringAttribute("D"), new StringAttribute("E")};
            ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);

            ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);

            Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

            EncryptionKey pk = kem.generateEncryptionKey((CiphertextIndex) policy);

            SetOfAttributes validAttributes = new SetOfAttributes();
            validAttributes.add(attributes[0]);
            validAttributes.add(attributes[3]);
            validAttributes.add(attributes[4]);

            DecryptionKey validSK = kem.generateDecryptionKey(setup.getMasterSecret(), validAttributes);

            KeyPair validKeyPair = new KeyPair(pk, validSK);

            StreamingHybridEncryptionScheme hybrid = new StreamingHybridEncryptionScheme(new StreamingGCMAES(), kem);

            FileInputStream plainIn = null;
            FileOutputStream cipherOut = null;

            FileInputStream cipherIn = null;
            FileOutputStream plainOut = null;

            try {
                byte[] plain = Files.readAllBytes(Paths.get(PT_PATH));
                plainIn = new FileInputStream(new File(PT_PATH));
                cipherOut = new FileOutputStream(new File(CT_PATH));
                hybrid.encrypt(plainIn, cipherOut, validKeyPair.getPk());
                plainIn.close();
                cipherOut.close();
                cipherIn = new FileInputStream(new File(CT_PATH));
                plainOut = new FileOutputStream(new File(TEMP_PT_PATH));
                hybrid.decrypt(cipherIn, plainOut, validKeyPair.getSk());
                cipherIn.close();
                plainOut.close();
                byte[] decryptedPlain = Files.readAllBytes(Paths.get(TEMP_PT_PATH));
                Assert.assertArrayEquals(plain, decryptedPlain);
                Files.deleteIfExists(Paths.get(CT_PATH));
            } catch (IOException e) {
                Assert.fail(e.getMessage());
            } finally {
                if (plainIn != null)
                    plainIn.close();
                if (cipherIn != null)
                    cipherIn.close();
                if (plainOut != null)
                    plainOut.close();
                if (cipherOut != null)
                    cipherOut.close();
                Files.deleteIfExists(Paths.get(TEMP_PT_PATH));
                Files.deleteIfExists(Paths.get(CT_PATH));

            }
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue(e instanceof UnsupportedOperationException);
        }

    }
}
