package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.math.structures.groups.Group;

/**
 * Generates an instance of the {@link SignatureSchemeParams} for the {@link SPSKPW15SignatureScheme}.
 */
public class SPSKPW15SignatureSchemeTestParamGenerator {

    public static SignatureSchemeParams generateParams(int securityParam, int numberOfMessages) {

        SPSKPW15PublicParameterGen ppSetup = new SPSKPW15PublicParameterGen();
        SPSKPW15PublicParameters pp = ppSetup.generatePublicParameter(securityParam, true, numberOfMessages);
        SPSKPW15SignatureScheme scheme = new SPSKPW15SignatureScheme(pp);

        SignatureKeyPair<SPSKPW15VerificationKey, SPSKPW15SigningKey> keyPair = scheme.generateKeyPair(numberOfMessages);
        SignatureKeyPair<SPSKPW15VerificationKey, SPSKPW15SigningKey> wrongKeyPair;

        do{
            wrongKeyPair = scheme.generateKeyPair(numberOfMessages);
        }while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
        || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

        Group G1 = pp.getG1GroupGenerator().getStructure();

        GroupElementPlainText[] messages = new GroupElementPlainText[numberOfMessages];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new GroupElementPlainText(G1.getUniformlyRandomElement());
        }

        GroupElementPlainText[] wrongMessages = new GroupElementPlainText[numberOfMessages];
        for (int i = 0; i < messages.length; i++) {
            do{
                wrongMessages[i] = new GroupElementPlainText(G1.getUniformlyRandomElement());
            }
            while (wrongMessages[i].equals(messages[i]));
        }

        MessageBlock messageBlock = new MessageBlock(messages);
        MessageBlock wrongMessageBlock = new MessageBlock(wrongMessages);

        return new SignatureSchemeParams(scheme, pp, messageBlock, wrongMessageBlock, keyPair, wrongKeyPair);
    }

}
