package de.upb.crypto.craco.enc;

import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.reflections.Reflections;

import java.lang.reflect.Modifier;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;


/**
 * Class for testing {@link EncryptionScheme} implementations. That includes classes that implement a subtype of
 * {@code EncryptionScheme} such as {@link StreamingEncryptionScheme}.
 * <p>
 * To use this class, implement a {@link TestParameterProvider} in the {@code params} folder in the same folder
 * as this class file.
 * The {@code TestParameterProvider}'s {@code get()} method should return a (or a list or array of)
 * {@link EncryptionSchemeTestParam}.
 * These testing parameters will be collected automatically by this tester via {@link #getParams()}
 * and used to test your {@code EncryptionScheme}.
 *
 * @author Raphael Heitjohann
 */
public class EncryptionSchemeTester {

    @ParameterizedTest
    @MethodSource("getParams")
    public void testEncryptDecrypt(EncryptionSchemeTestParam param) {
        System.out.println("Testing valid encrypt/decrypt for " + param.getClazz().getName());
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }

        PlainText data = param.getPlainText();
        // For randomized plaintexts its important to be able to reproduce the test using this representation
        System.out.println("Using plaintext " + new JSONConverter().serialize(data.getRepresentation()));

        DecryptionKey sk = param.getValidKeyPair().getSk();
        System.out.println("Using decryption key " + new JSONConverter().serialize(sk.getRepresentation()));
        EncryptionKey pk =  param.getValidKeyPair().getPk();
        System.out.println("Using encryption key " + new JSONConverter().serialize(pk.getRepresentation()));

        // Do an encryption/decryption run
        CipherText cipherText = param.getScheme().encrypt(data, pk);
        PlainText decryptedCipherText = param.getScheme().decrypt(cipherText, sk);
        assertEquals(data, decryptedCipherText);
    }

    @ParameterizedTest
    @MethodSource("getParams")
    public void testFailEncryptDecrypt(EncryptionSchemeTestParam param) {
        System.out.println("Testing invalid encrypt/decrypt for " + param.getClazz().getName());
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }

        PlainText data = param.getPlainText();
        // For randomized plaintexts its important to be able to reproduce the test using this representation
        System.out.println("Using plaintext " + new JSONConverter().serialize(data.getRepresentation()));

        DecryptionKey sk = param.getInvalidKeyPair().getSk();
        System.out.println("Using decryption key " + new JSONConverter().serialize(sk.getRepresentation()));
        EncryptionKey pk = param.getInvalidKeyPair().getPk();
        System.out.println("Using encryption key " + new JSONConverter().serialize(pk.getRepresentation()));

        // Do a encryption/decryption run
        CipherText cipherText = param.getScheme().encrypt(data, pk);
        try {
            PlainText decryptedCipherText = param.getScheme().decrypt(cipherText, sk);
            assertNotEquals(data, decryptedCipherText);
        } catch (Exception e) {
            System.out.println("Exception '" + e + "' was thrown during decryption");
            // used to assert an UnqualifiedKeyException here, but especially ABE schemes may throw other exceptions
        }
    }

    @ParameterizedTest
    @MethodSource("de.upb.crypto.craco.enc.EncryptionSchemeTester#getParams")
    public void testGetPlainText(EncryptionSchemeTestParam param) {
        System.out.println("Testing getPlainText() method for " + param.getClazz().getName());
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }

        PlainText plainText = param.getPlainText();
        // For randomized plaintexts its important to be able to reproduce the test using this representation
        System.out.println("Using plaintext " + new JSONConverter().serialize(plainText.getRepresentation()));
        PlainText reconstructedPlainText = param.getScheme().getPlainText(plainText.getRepresentation());
        assertEquals(
                plainText, reconstructedPlainText,
                "Reconstructed plaintext does not match actual plaintext"
        );
    }

    @ParameterizedTest
    @MethodSource("de.upb.crypto.craco.enc.EncryptionSchemeTester#getParams")
    public void testGetCipherText(EncryptionSchemeTestParam param) {
        System.out.println("Testing getCipherText() method for " + param.getClazz().getName());
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }

        PlainText plainText = param.getPlainText();
        // For randomized plaintexts its important to be able to reproduce the test using this representation
        System.out.println("Using plaintext " + new JSONConverter().serialize(plainText.getRepresentation()));

        EncryptionKey pk = param.getValidKeyPair().getPk();
        System.out.println("Using encryption key " + new JSONConverter().serialize(pk.getRepresentation()));

        CipherText cipherText = param.getScheme().encrypt(plainText, pk);

        CipherText reconstructedCipherText = param.getScheme().getCipherText(cipherText.getRepresentation());

        assertEquals(
                cipherText, reconstructedCipherText,
                "Reconstructed ciphertext does not match actual ciphertext"
        );
    }

    @ParameterizedTest
    @MethodSource("de.upb.crypto.craco.enc.EncryptionSchemeTester#getParams")
    public void testGetEncryptionKey(EncryptionSchemeTestParam param) {
        System.out.println("Testing getEncryptionKey() method for " + param.getClazz().getName());
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }

        EncryptionKey pk = param.getValidKeyPair().getPk();
        System.out.println("Using encryption key " + new JSONConverter().serialize(pk.getRepresentation()));

        EncryptionKey reconstructedPk = param.getScheme().getEncryptionKey(pk.getRepresentation());

        assertEquals(
                pk, reconstructedPk,
                "Reconstructed encryption key does not match actual encryption key"
        );
    }

    @ParameterizedTest
    @MethodSource("de.upb.crypto.craco.enc.EncryptionSchemeTester#getParams")
    public void testGetDecryptionKey(EncryptionSchemeTestParam param) {
        System.out.println("Testing getDecryptionKey() method for " + param.getClazz().getName());
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under test/de.upb.crypto.craco.enc.params" +
                    " or add it to the list in EncryptionSchemeTester#getEncryptionSchemeTestParams()");
        }

        DecryptionKey sk = param.getValidKeyPair().getSk();
        System.out.println("Using decryption key " + new JSONConverter().serialize(sk.getRepresentation()));

        DecryptionKey reconstructedSk = param.getScheme().getDecryptionKey(sk.getRepresentation());

        assertEquals(
                sk, reconstructedSk,
                "Reconstructed decryption key does not match actual decryption key"
        );

    }

    public static Stream<EncryptionSchemeTestParam> getParams() {
        // Get all classes that implement EncryptionScheme in Craco
        Reflections reflectionCraco = new Reflections("de.upb.crypto.craco");
        Set<Class<? extends EncryptionScheme>> schemeClasses =
                reflectionCraco.getSubTypesOf(EncryptionScheme.class);
        // Get all classes that provide parameters for the encryption scheme tests
        Reflections reflectionParams = new Reflections("de.upb.crypto.craco.enc.params");
        Set<Class<? extends TestParameterProvider>> paramProviderClasses =
                reflectionParams.getSubTypesOf(TestParameterProvider.class);

        // Fill the list of parameters used in test with the found parameters
        List<EncryptionSchemeTestParam> paramsToTest = new LinkedList<>();
        for (Class<? extends TestParameterProvider> providerClass : paramProviderClasses) {
            try {
                Object params = providerClass.newInstance().get();
                if (params instanceof Collection<?>) {
                    paramsToTest.addAll((Collection) params);
                } else if (params instanceof EncryptionSchemeTestParam[]) {
                    paramsToTest.addAll(Arrays.asList((EncryptionSchemeTestParam[]) params));
                } else if (params instanceof EncryptionSchemeTestParam) {
                    paramsToTest.add((EncryptionSchemeTestParam) params);
                } else {
                    System.out.println("Params for " + providerClass + " are not of type EncryptionSchemeTestParam");
                }
            } catch (InstantiationException | IllegalAccessException e) {
                System.out.println("Not able to instantiate encryption scheme test parameter provider " + providerClass
                        + " because of " + e);
            }
        }
        // ADD YOUR EXTERNAL PARAMETERS (outside of de.upb.crypto.craco.enc.params) HERE (to paramsToTest)

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
