package de.upb.crypto.craco.sig.hashthensign;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.hashthensign.HashThenSign;
import de.upb.crypto.craco.sig.SignatureSchemeTester;
import de.upb.crypto.craco.sig.hashthensign.params.BBSHTSParams;
import de.upb.crypto.craco.sig.hashthensign.params.HashThenSignParams;
import de.upb.crypto.craco.sig.hashthensign.params.PSHTSParams;
import de.upb.crypto.craco.sig.SignatureKeyPair;
import de.upb.crypto.craco.sig.SignatureScheme;
import de.upb.crypto.craco.sig.SigningKey;
import de.upb.crypto.craco.sig.VerificationKey;
import de.upb.crypto.math.hash.HashFunction;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Test for the {@link HashThenSign} construction. Each combination of {@link SignatureScheme} and {@link HashFunction}
 * to be tested need to be specified using {@link HashThenSignParams}.
 */
@RunWith(value = Parameterized.class)
public class HashThenSignTest {
    private SignatureScheme hashThenSign;

    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair1;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair2;

    private ByteArrayImplementation message1;
    private ByteArrayImplementation message2;

    public HashThenSignTest(HashThenSignParams params) {
        this.hashThenSign = new HashThenSign(params.getHashFunction(), params.getSignatureScheme());
        this.keyPair1 = params.getKeyPair1();
        this.keyPair2 = params.getKeyPair2();
        this.message1 = (ByteArrayImplementation) params.getMessage1();
        this.message2 = (ByteArrayImplementation) params.getMessage2();
    }

    /**
     * Each scheme to be tested needs to be added to the list output by this method.
     *
     * @return list of {@link HashThenSignParams} specifying schemes to be tested
     */
    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<HashThenSignParams> data() {
        ArrayList<HashThenSignParams> schemesToTest = new ArrayList<>();

        schemesToTest.addAll(PSHTSParams.getParams());
        schemesToTest.addAll(BBSHTSParams.getParams());

        return schemesToTest;
    }

    @Test
    public void testSignAndVerify() {
        // assert correction of the signature scheme
        SignatureSchemeTester.testSignatureSchemeSignAndVerify(hashThenSign, message1, keyPair1.getVerificationKey(),
                keyPair1.getSigningKey());
    }

    @Test
    public void testNegativeSignAndVerifyWrongMesssage() {
        // negative test: verifying a signature on the correct verification key, but wrong message -> verify fails?
        SignatureSchemeTester.testNegativeWrongMessageSignatureSchemeSignAndVerify(hashThenSign, message1, message2,
                keyPair1.getVerificationKey(), keyPair1.getSigningKey());
    }

    @Test
    public void testNegativeSignAndVerifyWrongKeys() {
        // negative test: verifying a signature with the wrong verification key -> verify fails?
        SignatureSchemeTester.testNegativeWrongKeysSignatureSchemeSignAndVerify(hashThenSign, message1,
                keyPair1.getVerificationKey(), keyPair1.getSigningKey(), keyPair2.getVerificationKey(),
                keyPair2.getSigningKey());
    }

    @Test
    public void testRepresentations() {
        // Test the standard representation of a signature scheme
        SignatureSchemeTester.testRepresentationSignatureScheme(hashThenSign, message1, keyPair1.getVerificationKey(),
                keyPair1.getSigningKey());
    }
}
