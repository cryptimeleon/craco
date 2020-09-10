package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSPublicParametersGen;

public class PS18SignatureSchemeVectorTestParamGen {

    /**
     * Generates an instance of the {@link SignatureSchemeParams} for the
     * {@link PS18SignatureSchemeVector}.
     *
     * @param securityParam Security parameter.
     * @param numMessages Length of message vector the scheme should support.
     * @return Instance of the {@link SignatureSchemeParams}.
     */
    public static SignatureSchemeParams generateParams(int securityParam, int numMessages) {
        PSPublicParametersGen ppGen = new PSPublicParametersGen();
        PSPublicParameters pp = ppGen.generatePublicParameter(securityParam, true);
        PS18SignatureSchemeVector psScheme = new PS18SignatureSchemeVector(pp);

        SignatureKeyPair<? extends PS18VerificationKeyVector, ? extends PS18SigningKey> keyPair =
                psScheme.generateKeyPairVector(numMessages);
        SignatureKeyPair<? extends PS18VerificationKeyVector, ? extends PS18SigningKey> wrongKeyPair;
        do {
            wrongKeyPair = psScheme.generateKeyPairVector(numMessages);
        } while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

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
