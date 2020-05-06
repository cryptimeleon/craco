package de.upb.crypto.craco.ser.test;

import de.upb.crypto.craco.interfaces.*;
import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.math.serialization.Representation;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(value = Parameterized.class)
public class RepresentationTest {

    protected EncryptionScheme scheme;
    protected EncryptionKey encryptionKey;
    protected DecryptionKey decryptionKey;
    protected PlainText plainText;
    protected CipherText cipherText;
    protected MasterSecret masterSecret;

    public RepresentationTest(RepresentationTestParams params) {
        scheme = params.scheme;
        encryptionKey = params.encryptionKey;
        decryptionKey = params.decryptionKey;
        plainText = params.plainText;
        cipherText = params.cipherText;
        masterSecret = params.masterSecret;
    }

    @Test
    public void testRepresentation() throws InstantiationException, IllegalAccessException, IllegalArgumentException,
            InvocationTargetException, NoSuchMethodException, SecurityException {
        System.out.println("Testing " + scheme.getRepresentedTypeName());
        // Testing standalone of the scheme
        EncryptionScheme toCompare =
                scheme.getClass().getConstructor(Representation.class).newInstance(scheme.getRepresentation());
        System.out.println("Testing the standalone property of the scheme...");
        assertEquals(scheme, toCompare);
        //testing the representations of the scheme
        System.out.println("Testing the deserialization of an EncryptionKey...");
        assertEquals(encryptionKey, scheme.getEncryptionKey(encryptionKey.getRepresentation()));
        System.out.println("Testing the deserialization of a DecryptionKey...");
        assertEquals(decryptionKey, scheme.getDecryptionKey(decryptionKey.getRepresentation()));
        System.out.println("Testing the deserialization of a PlainText...");
        assertEquals(plainText, scheme.getPlainText(plainText.getRepresentation()));
        System.out.println("Testing the deserialization of a CipherText...");
        assertEquals(cipherText, scheme.getCipherText(cipherText.getRepresentation()));
        if (scheme instanceof PredicateEncryptionScheme) {
            PredicateEncryptionScheme predScheme = (PredicateEncryptionScheme) scheme;
            System.out.println("Testing the deserialization of a MasterSecret...");
            assertEquals(masterSecret, predScheme.getMasterSecret(masterSecret.getRepresentation()));
        }

    }

    @Parameters(name = "{index}: {0}")
    public static Collection<RepresentationTestParams> data() {

        ArrayList<RepresentationTestParams> toReturn = new ArrayList<>();
        toReturn.add(ABEKPGPSW06SmallParams.getParams());
        toReturn.add(ABECPWat11SmallParams.getParams());
        toReturn.add(ABECPWat11Params.getParams());
        toReturn.add(ElgamalParams.getParams());
        toReturn.add(ABEKPGPSW06Params.getParams());
        toReturn.add(IBEFuzzySW05SmallParams.getParams());
        toReturn.add(IBEFuzzySW05Params.getParams());
        toReturn.add(FullIdentParams.getParams());
        toReturn.add(ABECPWat11AsymSmallParams.getParams());
        return toReturn;
    }
}
