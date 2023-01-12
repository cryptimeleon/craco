package org.cryptimeleon.craco.sig.ecdsa;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;

public class ECDSASignatureSchemeTestParamGen {

    /**
     * Generates an instance of the {@link SignatureSchemeParams} for the
     * {@link ECDSASignatureScheme}.
     *
     * @return Instance of the {@link SignatureSchemeParams}.
     */
    public static SignatureSchemeParams generateParams() {
        ECDSASignatureScheme ecdsaSignatureScheme = new ECDSASignatureScheme();

        SignatureKeyPair<ECDSAVerificationKey, ECDSASigningKey> keyPair = ecdsaSignatureScheme.generateKeyPair();
        SignatureKeyPair<ECDSAVerificationKey, ECDSASigningKey> wrongKeyPair;
        do {
            wrongKeyPair = ecdsaSignatureScheme.generateKeyPair();
        } while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

        MessageBlock plainText = new MessageBlock(new ByteArrayImplementation("Valid Message".getBytes()));
        MessageBlock wrongPlainText = new MessageBlock(new ByteArrayImplementation("Invalid Message".getBytes()));


        // ECDSA does not use PP since it is a fixed instance
        return new SignatureSchemeParams(ecdsaSignatureScheme, null, plainText, wrongPlainText, keyPair, wrongKeyPair);
    }
}
