package org.cryptimeleon.craco.sig.sps.eq;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;

/**
 * Generates an instance of the {@link SignatureSchemeParams} for the {@link SPSEQSignatureScheme}.
 */
public class SPSEQSignatureSchemeTestParamGenerator {
    public static SignatureSchemeParams generateParams(int securityParam, int numMessages) {
        // setup scheme
        SPSEQPublicParametersGen ppSetup = new SPSEQPublicParametersGen();
        SPSEQPublicParameters pp = ppSetup.generatePublicParameter(securityParam, true);
        SPSEQSignatureScheme spseqScheme = new SPSEQSignatureScheme(pp);

        // generate two different key pairs to test
        SignatureKeyPair<? extends SPSEQVerificationKey, ? extends SPSEQSigningKey> keyPair = spseqScheme.generateKeyPair(
                numMessages);
        SignatureKeyPair<? extends SPSEQVerificationKey, ? extends SPSEQSigningKey> wrongKeyPair;
        do {
            wrongKeyPair = spseqScheme.generateKeyPair(numMessages);
        } while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

        // generate two different message blocks to test
        GroupElementPlainText[] messages = new GroupElementPlainText[numMessages];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new GroupElementPlainText(pp.getBilinearMap().getG1().getUniformlyRandomElement());
        }
        MessageBlock messageBlock = new MessageBlock(messages);

        GroupElementPlainText[] wrongMessages = new GroupElementPlainText[numMessages];
        for (int i = 0; i < wrongMessages.length; i++) {
            do {
                wrongMessages[i] = new GroupElementPlainText(pp.getBilinearMap().getG1().getUniformlyRandomElement());
            } while (wrongMessages[i].equals(messages[i]));
        }
        MessageBlock wrongMessageBlock = new MessageBlock(wrongMessages);

        return new SignatureSchemeParams(spseqScheme, pp, messageBlock, wrongMessageBlock, keyPair, wrongKeyPair);
    }
}
