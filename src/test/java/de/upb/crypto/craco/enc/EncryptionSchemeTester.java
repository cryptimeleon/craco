package de.upb.crypto.craco.enc;

import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.*;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.reflections.Reflections;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Modifier;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.Assert.*;

public class EncryptionSchemeTester {

    @ParameterizedTest
    @MethodSource("getEncryptionSchemeTestParams")
    public void testEncryptDecrypt(EncryptionSchemeTestParam param) {
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }
        System.out.println("Testing valid encrypt/decrypt for " + param.getClazz().getName() + " ...");
        PlainText data = param.getPlainTextSupplier().get();

        DecryptionKey sk = param.getValidKeyPair().getSk();
        EncryptionKey pk =  param.getValidKeyPair().getPk();

        // Do an encryption/decryption run
        CipherText cipherText = param.getScheme().encrypt(data, pk);
        PlainText decryptedCipherText = param.getScheme().decrypt(cipherText, sk);
        assertEquals(data, decryptedCipherText);
    }

    @ParameterizedTest
    @MethodSource("getEncryptionSchemeTestParams")
    public void testFailEncryptDecrypt(EncryptionSchemeTestParam param) {
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }
        System.out.println("Testing invalid encrypt/decrypt for " + param.getClazz().getName() + " ...");

        PlainText data = param.getPlainTextSupplier().get();

        DecryptionKey sk = param.getInvalidKeyPair().getSk();
        EncryptionKey pk = param.getInvalidKeyPair().getPk();

        // Do a encryption/decryption run
        CipherText cipherText = param.getScheme().encrypt(data, pk);
        try {
            PlainText decryptedCipherText = param.getScheme().decrypt(cipherText, sk);
            assertNotEquals(data, decryptedCipherText);
        } catch (Exception e) {
            assertTrue(e instanceof UnqualifiedKeyException); // schemes should throw UnqualifiedKeyExceptions if the
                                                              // key is not fit to decrypt.
        }
    }

    public static Stream<EncryptionSchemeTestParam> getEncryptionSchemeTestParams() {
        // Get all classes that implement GroupSignatureScheme in Craco
        Reflections reflectionCraco = new Reflections("de.upb.crypto.craco");
        Set<Class<? extends EncryptionScheme>> schemeClasses =
                reflectionCraco.getSubTypesOf(EncryptionScheme.class);
        // Get all classes that provide parameters for the group signature scheme tests
        Reflections reflectionParams = new Reflections("de.upb.crypto.craco.enc.params");
        Set<Class<? extends TestParameterProvider>> paramProviderClasses =
                reflectionParams.getSubTypesOf(TestParameterProvider.class);

        // Fill the list of parameters used in test with the found parameters
        List<EncryptionSchemeTestParam> paramsToTest = new LinkedList<>();
        for (Class<? extends TestParameterProvider> providerClass : paramProviderClasses) {
            try {
                Object params = providerClass.newInstance().get();
                paramsToTest.add((EncryptionSchemeTestParam) params);
            } catch (InstantiationException | IllegalAccessException e) {
                System.out.println("Not able to instantiate GroupSignatureTestParameterProvider " + providerClass
                        + " because of " + e);
            } catch (ClassCastException e) {
                System.out.println("Not able to cast test params provided by " + providerClass
                        + " to GroupSignatureTestParam");
            }
        }

        // Remove all schemes that have parameters provided from the list of classes
        for (EncryptionSchemeTestParam param : paramsToTest) {
            schemeClasses.remove(param.getScheme().getClass());
        }

        // Classes without provided parameters have empty params that will force an error in the test
        for (Class<? extends EncryptionScheme> clazz : schemeClasses) {
            if (!clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
                paramsToTest.add(new EncryptionSchemeTestParam(clazz));
            }
        }
        return paramsToTest.stream();
    }
}
