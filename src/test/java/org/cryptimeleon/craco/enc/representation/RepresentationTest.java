package org.cryptimeleon.craco.enc.representation;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.EncryptionScheme;
import org.cryptimeleon.math.serialization.Representation;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(value = Parameterized.class)
public class RepresentationTest {

    protected EncryptionScheme scheme;
    protected EncryptionKey encryptionKey;
    protected DecryptionKey decryptionKey;
    protected PlainText plainText;
    protected CipherText cipherText;

    public RepresentationTest(RepresentationTestParams params) {
        scheme = params.scheme;
        encryptionKey = params.encryptionKey;
        decryptionKey = params.decryptionKey;
        plainText = params.plainText;
        cipherText = params.cipherText;
    }

    @Test
    public void testRepresentation() throws InstantiationException, IllegalAccessException, IllegalArgumentException,
            InvocationTargetException, NoSuchMethodException, SecurityException {
        System.out.println("Testing " + scheme.toString());
        // Testing standalone of the scheme
        EncryptionScheme toCompare =
                scheme.getClass().getConstructor(Representation.class).newInstance(scheme.getRepresentation());
        System.out.println("Testing the standalone property of the scheme...");
        assertEquals(scheme, toCompare);
        //testing the representations of the scheme
        System.out.println("Testing the deserialization of an EncryptionKey...");
        assertEquals(encryptionKey, scheme.restoreEncryptionKey(encryptionKey.getRepresentation()));
        System.out.println("Testing the deserialization of a DecryptionKey...");
        assertEquals(decryptionKey, scheme.restoreDecryptionKey(decryptionKey.getRepresentation()));
        System.out.println("Testing the deserialization of a PlainText...");
        assertEquals(plainText, scheme.restorePlainText(plainText.getRepresentation()));
        System.out.println("Testing the deserialization of a CipherText...");
        assertEquals(cipherText, scheme.restoreCipherText(cipherText.getRepresentation()));
    }

    @Parameters(name = "{index}: {0}")
    public static Collection<RepresentationTestParams> data() {
        ArrayList<RepresentationTestParams> toReturn = new ArrayList<>();
        toReturn.add(ElgamalParams.getParams());
        return toReturn;
    }
}
