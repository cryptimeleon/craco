package de.upb.crypto.craco.sig;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.sig.interfaces.*;
import de.upb.crypto.math.random.interfaces.RandomGeneratorSupplier;
import de.upb.crypto.math.serialization.Representation;

import java.util.Arrays;

import static org.junit.Assert.*;


public class SignatureSchemeTester {

    /**
     * Test checking that given a {@link SignatureScheme}, its {@link SigningKey} and {@link VerificationKey}, a
     * given {@link PlainText} can be signed, and that the resulting signature can be successfully verified.
     *
     * @param signatureScheme {@link SignatureScheme} to be checked
     * @param plainText       {@link PlainText} to be signed
     * @param verificationKey {@link VerificationKey} of for the tested {@link SignatureScheme} and {@link SigningKey}
     * @param signingKey      {@link SigningKey} of for the tested {@link SignatureScheme} and {@link VerificationKey}
     * @return Successfully created and verified {@link Signature} for a given {@link PlainText}
     */
    public static Signature testSignatureSchemeSignAndVerify(SignatureScheme signatureScheme, PlainText plainText,
                                                             VerificationKey verificationKey, SigningKey signingKey) {

        Signature signature = signatureScheme.sign(plainText, signingKey);
        assertTrue(signatureScheme.verify(plainText, signature, verificationKey));
        return signature;
    }

    /**
     * Test checking the representations of a {@link Signature}, a {@link SigningKey} and a {@link VerificationKey}
     * equal their original instances and that given a {@link SignatureScheme} still verifies the recreated instances
     * successfully.
     *
     * @param signatureScheme {@link SignatureScheme}
     * @param plainText       {@link PlainText} to be signed
     * @param verificationKey {@link VerificationKey} of for the tested {@link SignatureScheme} and {@link SigningKey}
     * @param signingKey      {@link SigningKey} of for the tested {@link SignatureScheme} and {@link VerificationKey}
     */
    public static void testRepresentationSignatureScheme(SignatureScheme signatureScheme,
                                                         PlainText plainText,
                                                         VerificationKey verificationKey,
                                                         SigningKey signingKey) {
        // Test representations for a signature
        Signature signature = signatureScheme.sign(plainText, signingKey);
        Representation signatureRepresentation = signature.getRepresentation();
        Signature signatureFromRepr = signatureScheme.getSignature(signatureRepresentation);
        assertEquals(signature, signatureFromRepr);

        // Test representation for a signing key
        Representation signingKeyRepresentation = signingKey.getRepresentation();
        SigningKey signingKeyFromRepr = signatureScheme.getSigningKey(signingKeyRepresentation);
        assertEquals(signingKey, signingKeyFromRepr);

        // Test representation for a verification key
        Representation verificationKeyRepresentation = verificationKey.getRepresentation();
        VerificationKey verificationKeyFromRepr = signatureScheme.getVerificationKey(verificationKeyRepresentation);
        assertEquals(verificationKey, verificationKeyFromRepr);

        // Test representation for a plaintext
        Representation plainTextRepresentation = plainText.getRepresentation();
        PlainText plainTextFromRepr = signatureScheme.getPlainText(plainTextRepresentation);
        assertEquals(plainText, plainTextFromRepr);

    }

    /**
     * Test signing one {@link PlainText} and using this {@link Signature} to check that
     * {@link SignatureScheme#verify} returns false for a different {@link PlainText}
     *
     * @param signatureScheme {@link SignatureScheme} to be checked
     * @param plainText       {@link PlainText} to be signed
     * @param wrongPlainText  different {@link PlainText} which will be verified with the other {@link PlainText}'s
     *                        {@link Signature}
     * @param verificationKey {@link VerificationKey} of for the tested {@link SignatureScheme} and {@link SigningKey}
     * @param signingKey      {@link SigningKey} of for the tested {@link SignatureScheme} and {@link VerificationKey}
     */
    public static void testNegativeWrongMessageSignatureSchemeSignAndVerify(SignatureScheme signatureScheme,
                                                                            PlainText plainText,
                                                                            PlainText wrongPlainText,
                                                                            VerificationKey verificationKey,
                                                                            SigningKey signingKey) {
        Signature signature = signatureScheme.sign(plainText, signingKey);
        assertFalse(signatureScheme.verify(wrongPlainText, signature, verificationKey));
    }

    /**
     * Test using two different {@link SignatureKeyPair}. The
     * {@link PlainText} is
     * signed with each {@link SigningKey}, thus creating to {@link Signature}s.
     * Then it is checked that {@link SignatureScheme#verify} returns false for invalid combinations of
     * {@link Signature}s and {@link VerificationKey}s
     *
     * @param signatureScheme      {@link SignatureScheme} to be checked
     * @param plainText            {@link PlainText} to be signed
     * @param verificationKey      {@link VerificationKey} of for the tested {@link SignatureScheme} and
     *                             {@link SigningKey}
     * @param signingKey           {@link SigningKey} of for the tested {@link SignatureScheme} and
     *                             {@link VerificationKey}
     * @param wrongVerificationKey different {@link VerificationKey} of for the tested {@link SignatureScheme} and
     *                             {@link SigningKey}
     * @param wrongSigningKey      different {@link SigningKey} of for the tested {@link SignatureScheme} and
     *                             {@link VerificationKey}
     */
    public static void testNegativeWrongKeysSignatureSchemeSignAndVerify(SignatureScheme signatureScheme,
                                                                         PlainText plainText,
                                                                         VerificationKey verificationKey,
                                                                         SigningKey signingKey,
                                                                         VerificationKey wrongVerificationKey,
                                                                         SigningKey wrongSigningKey) {
        // wrong verification key
        Signature signature = signatureScheme.sign(plainText, signingKey);
        assertFalse(signatureScheme.verify(plainText, signature, wrongVerificationKey));

        // wrong signing key
        Signature wrongSignature = signatureScheme.sign(plainText, wrongSigningKey);
        assertFalse(signatureScheme.verify(plainText, wrongSignature, verificationKey));
    }

    /**
     * Test for {@link SignatureScheme#mapToPlaintext}. This particular test asserts the general functionality of
     * mapToPlaintext.
     */
    public static void testMapToPlaintext(SignatureScheme sig, VerificationKey pk) {
        byte[] randomBytes1 =
                RandomGeneratorSupplier.getRnd().getRandomByteArray(sig.getMaxNumberOfBytesForMapToPlaintext());
        byte[] randomBytes2;
        do {
            randomBytes2 =
                    RandomGeneratorSupplier.getRnd().getRandomByteArray(sig.getMaxNumberOfBytesForMapToPlaintext());
        } while (Arrays.equals(randomBytes1, randomBytes2));

        // different arrays of the same length yield different plaintext
        assertNotEquals(sig.mapToPlaintext(randomBytes1, pk), sig.mapToPlaintext(randomBytes2, pk));
    }

    /**
     * Test for {@link SignatureScheme#mapToPlaintext}. This particular test asserts the contract stated for
     * {@link SignatureScheme#mapToPlaintext} that says for a valid key pair (pk, sk) and byte array b, it holds
     * <p>
     * mapToPlaintext(b , pk) == mapToPlaintext(b, sk)
     */
    public static void testMapToPlainTextContract(SignatureScheme sig, SignatureKeyPair keyPair) {
        byte[] randomBytes =
                RandomGeneratorSupplier.getRnd().getRandomByteArray(sig.getMaxNumberOfBytesForMapToPlaintext());

        assertEquals(sig.mapToPlaintext(randomBytes, keyPair.getVerificationKey()),
                sig.mapToPlaintext(randomBytes, keyPair.getSigningKey()));
    }
}
