package org.cryptimeleon.craco.sig.sps.akot15;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme;
import org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2VerificationKey;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.*;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class SPSAKOT15SignatureSchemeTestParameterGenerator {

    public static SignatureSchemeParams generateParameters(int securityParameter, int messageLength) {
        // setup scheme

        AKOT15SharedPublicParameters pp = AKOT15SharedPublicParametersGen.generateParameters(
                securityParameter, messageLength, true
        );

        SPSFSP2SignatureScheme scheme = new SPSFSP2SignatureScheme(pp);


        SignatureKeyPair<SPSFSP2VerificationKey, SPSXSIGSigningKey> keyPair = scheme.generateKeyPair(
                messageLength);

        SignatureKeyPair<SPSFSP2VerificationKey, SPSXSIGSigningKey> wrongKeyPair;

        do{
            wrongKeyPair = scheme.generateKeyPair(messageLength);
        }while(
                wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                        || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey())
        );

        // generate two different messages

        GroupElementPlainText[] messages = new GroupElementPlainText[messageLength];

        for (int i = 0; i < messages.length; i++) {
            messages[i] = new GroupElementPlainText(pp.getG2GroupGenerator().pow(pp.getZp().getUniformlyRandomElement()).compute());
        }

        GroupElementPlainText[] wrongMessages = new GroupElementPlainText[messageLength];

        for (int i = 0; i < wrongMessages.length; i++) {

            do {
                wrongMessages[i] = new GroupElementPlainText(pp.getG2GroupGenerator().pow(pp.getZp().getUniformlyRandomElement()).compute());

            }while(wrongMessages[i].equals(messages[i]));
        }

        return new SignatureSchemeParams(
                scheme,
                pp,
                new MessageBlock(messages),
                new MessageBlock(wrongMessages),
                keyPair,
                wrongKeyPair
        );
    }

}
