package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;

/**
 * Generates an instance of the {@link SignatureSchemeParams} for the {@link SPSGroth15SignatureScheme}.
 */
public class SPSGroth15SignatureSchemeTestParamGenerator {
    public static SignatureSchemeParams generateParams(int securityParam, SPSGroth15PublicParametersGen.Groth15Type type, int numberOfMessages) {
        // setup scheme
        SPSGroth15PublicParametersGen ppSetup = new SPSGroth15PublicParametersGen();
        SPSGroth15PublicParameters pp = ppSetup.generatePublicParameter(securityParam, type, numberOfMessages, true);
        SPSGroth15SignatureScheme scheme = new SPSGroth15SignatureScheme(pp);

        // generate two different key pairs to test
        SignatureKeyPair<? extends SPSGroth15VerificationKey, ? extends SPSGroth15SigningKey> keyPair = scheme.generateKeyPair(
                numberOfMessages);
        SignatureKeyPair<? extends SPSGroth15VerificationKey, ? extends SPSGroth15SigningKey> wrongKeyPair;
        do {
            wrongKeyPair = scheme.generateKeyPair(numberOfMessages);
        } while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

        // generate two different message blocks to test
        GroupElementPlainText[] messages = new GroupElementPlainText[numberOfMessages];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new GroupElementPlainText(pp.getPlaintextGroupGenerator().getStructure().getUniformlyRandomElement());
        }
        MessageBlock messageBlock = new MessageBlock(messages);

        GroupElementPlainText[] wrongMessages = new GroupElementPlainText[numberOfMessages];
        for (int i = 0; i < wrongMessages.length; i++) {
            do {
                wrongMessages[i] = new GroupElementPlainText(pp.getPlaintextGroupGenerator().getStructure().getUniformlyRandomElement());
            } while (wrongMessages[i].equals(messages[i]));
        }
        MessageBlock wrongMessageBlock = new MessageBlock(wrongMessages);

        return new SignatureSchemeParams(scheme, pp, messageBlock, wrongMessageBlock, keyPair, wrongKeyPair);
    }
}
