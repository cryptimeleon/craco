package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSigningKey;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGVerificationKey;

public class SPSPOSSignatureSchemeTestParamGenerator {

    public static SignatureSchemeParams generateParameters(int securityParameter, int numberOfMessages) {

        // setup scheme
        SPSPOSPublicParameters pp = SPSPOSPublicParametersGen.generateParameters(securityParameter, numberOfMessages, true);
        SPSPOSSignatureScheme scheme = new SPSPOSSignatureScheme(pp);

        SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey> keyPair = scheme.generateKeyPair(numberOfMessages);

        SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey> wrongKeyPair;
        do{
            wrongKeyPair = scheme.generateKeyPair(numberOfMessages);
        }while(
                wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                        || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey())
        );

        // generate two different messages

        GroupElementPlainText[] messages = new GroupElementPlainText[numberOfMessages];

        for (int i = 0; i < messages.length; i++) {
            messages[i] = new GroupElementPlainText(pp.getG2GroupGenerator().getStructure().getUniformlyRandomElement());
        }

        GroupElementPlainText[] wrongMessages = new GroupElementPlainText[numberOfMessages];

        for (int i = 0; i < wrongMessages.length; i++) {

            do{
                wrongMessages[i] = new GroupElementPlainText(pp.getG2GroupGenerator().getStructure().getUniformlyRandomElement());
            }while(
                    wrongMessages[i].equals(messages[i])
            );
        }

        return new SignatureSchemeParams(
                scheme,
                pp,
                new MessageBlock(messages),
                new MessageBlock(wrongMessages),
                keyPair,
                wrongKeyPair);

    }

}
