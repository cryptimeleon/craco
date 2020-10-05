package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.interfaces.SignatureKeyPair;

/**
 * Generates an instance of the {@link SignatureSchemeParams} for the {@link PSSignatureScheme}.
 */
public class PSSignatureSchemeTestParamGenerator {
    public static SignatureSchemeParams generateParams(int securityParam, int numMessages) {
        // setup scheme
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        PSPublicParameters pp = ppSetup.generatePublicParameter(securityParam, true);
        PSSignatureScheme psScheme = new PSSignatureScheme(pp);

        // generate two different key pairs to test
        SignatureKeyPair<? extends PSVerificationKey, ? extends PSSigningKey> keyPair = psScheme.generateKeyPair(
                numMessages);
        SignatureKeyPair<? extends PSVerificationKey, ? extends PSSigningKey> wrongKeyPair;
        do {
            wrongKeyPair = psScheme.generateKeyPair(numMessages);
        } while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

        // generate two different message blocks to test
        RingElementPlainText[] messages = new RingElementPlainText[numMessages];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new RingElementPlainText(pp.getZp().getUniformlyRandomElement());
        }
        MessageBlock messageBlock = new MessageBlock(messages);

        RingElementPlainText[] wrongMessages = new RingElementPlainText[numMessages];
        for (int i = 0; i < wrongMessages.length; i++) {
            do {
                wrongMessages[i] = new RingElementPlainText(pp.getZp().getUniformlyRandomElement());
            } while (wrongMessages[i].equals(messages[i]));
        }
        MessageBlock wrongMessageBlock = new MessageBlock(wrongMessages);

        return new SignatureSchemeParams(psScheme, pp, messageBlock, wrongMessageBlock, keyPair, wrongKeyPair);
    }
}
