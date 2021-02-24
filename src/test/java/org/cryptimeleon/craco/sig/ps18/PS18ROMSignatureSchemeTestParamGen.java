package org.cryptimeleon.craco.sig.ps18;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.ps.PSPublicParameters;
import org.cryptimeleon.craco.sig.ps.PSPublicParametersGen;

public class PS18ROMSignatureSchemeTestParamGen {
    /**
     * Generates an instance of the {@link SignatureSchemeParams} for the
     * {@link PS18ROMSignatureScheme}.
     *
     * @param securityParam Security parameter.
     * @param numMessages Length of message vector the scheme should support.
     * @return Instance of the {@link SignatureSchemeParams}.
     */
    public static SignatureSchemeParams generateParams(int securityParam, int numMessages) {
        PSPublicParametersGen ppGen = new PSPublicParametersGen();
        PSPublicParameters pp = ppGen.generatePublicParameter(securityParam, true);
        PS18ROMSignatureScheme psScheme = new PS18ROMSignatureScheme(pp);

        SignatureKeyPair<? extends PS18VerificationKey, ? extends PS18SigningKey> keyPair =
                psScheme.generateKeyPair(numMessages);
        SignatureKeyPair<? extends PS18VerificationKey, ? extends PS18SigningKey> wrongKeyPair;
        do {
            wrongKeyPair = psScheme.generateKeyPair(numMessages);
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
