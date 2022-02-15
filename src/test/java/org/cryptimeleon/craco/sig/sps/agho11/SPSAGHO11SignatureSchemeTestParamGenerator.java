package org.cryptimeleon.craco.sig.sps.agho11;


import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;

import java.util.Arrays;

public class SPSAGHO11SignatureSchemeTestParamGenerator {

    /**
     * Generate a set of parameters used for testing the scheme
     * */
    public static SignatureSchemeParams generateParams(int securityParameter, Integer[] messageBlockLengths){

        //setup scheme
        SPSAGHO11PublicParametersGen ppSetup = new SPSAGHO11PublicParametersGen();
        SPSAGHO11PublicParameters pp = SPSAGHO11PublicParametersGen.generatePublicParameters(securityParameter, true, messageBlockLengths);
        SPSAGHO11SignatureScheme scheme = new SPSAGHO11SignatureScheme(pp);

        //generate two different key pairs to test
        int[] msgBlockLengths = Arrays.stream(messageBlockLengths).mapToInt(i->i).toArray();

        SignatureKeyPair<? extends SPSAGHO11VerificationKey, ? extends SPSAGHO11SigningKey> keyPair =
                scheme.generateKeyPair(msgBlockLengths);

        SignatureKeyPair<? extends SPSAGHO11VerificationKey, ? extends SPSAGHO11SigningKey> wrongKeyPair;

        do{
            wrongKeyPair = scheme.generateKeyPair(msgBlockLengths);
        }
        while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

        //generate two different message blocks for testing

        // first element is the valid message, second the invalid message
        MessageBlock[] testMessages = generateMessageBlocks(pp, messageBlockLengths);

        return new SignatureSchemeParams(scheme, pp, testMessages[0], testMessages[1], keyPair, wrongKeyPair);
    }


    /**
     * Generate two message blocks of a given length to be used for testing.
     * */
    private static MessageBlock[] generateMessageBlocks(SPSAGHO11PublicParameters pp, Integer[] messageBlockLengths) {

        MessageBlock[] groupElementVectors = new MessageBlock[2];

        for (int i = 0; i < 2; i++) {

            GroupElementPlainText[] innerBlock = new GroupElementPlainText[messageBlockLengths[i]];

            for (int j = 0; j < messageBlockLengths[i]; j++) {
                if(i == 0)
                    innerBlock[j] = new GroupElementPlainText(pp.getG1GroupGenerator().getStructure().getUniformlyRandomElement());
                else
                    innerBlock[j] = new GroupElementPlainText(pp.getG2GroupGenerator().getStructure().getUniformlyRandomElement());
            }

            groupElementVectors[i] = new MessageBlock(innerBlock);
        }

        MessageBlock[] wrongGroupElementVectors = new MessageBlock[2];

        for (int i = 0; i < 2; i++) {

            GroupElementPlainText[] wrongInnerBlock = new GroupElementPlainText[messageBlockLengths[i]];

            for (int j = 0; j < messageBlockLengths[i]; j++) {
                do{
                    if(i == 0)
                        wrongInnerBlock[j] = new GroupElementPlainText(pp.getG1GroupGenerator().getStructure().getUniformlyRandomElement());
                    else
                        wrongInnerBlock[j] = new GroupElementPlainText(pp.getG2GroupGenerator().getStructure().getUniformlyRandomElement());
                }
                while(wrongInnerBlock[j].equals(groupElementVectors[i].get(j)));
            }

            wrongGroupElementVectors[i] = new MessageBlock(wrongInnerBlock);
        }

        return new MessageBlock[] {new MessageBlock(groupElementVectors), new MessageBlock(wrongGroupElementVectors)};
    }

}
