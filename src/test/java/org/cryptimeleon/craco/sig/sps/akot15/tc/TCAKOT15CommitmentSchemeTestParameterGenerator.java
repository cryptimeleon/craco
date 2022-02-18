package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.CommitmentKey;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class TCAKOT15CommitmentSchemeTestParameterGenerator {

    public static TrapdoorCommitmentTestParameters generateParameters(int securityParameter, int messageLength) {

        TCAKOT15PublicParameters pp = TCAKOT15PublicParametersGen.generateParameters(securityParameter, messageLength, true);

        TCAKOT15CommitmentScheme scheme = new TCAKOT15CommitmentScheme(pp);

        CommitmentKey CommitmentKey = scheme.generateKey();

        //generate messages

        GroupElementPlainText[] messages = new GroupElementPlainText[messageLength];

        Zp zp = pp.getZp();

        for (int i = 0; i < messageLength; i++) {
            messages[i] = new GroupElementPlainText(pp.getG2GroupGenerator().pow(zp.getUniformlyRandomElement()));
        }

        GroupElementPlainText[] wrongMessages = new GroupElementPlainText[messageLength];

        for (int i = 0; i < messageLength; i++) {

            do {
                wrongMessages[i] = new GroupElementPlainText(pp.getG2GroupGenerator().pow(zp.getUniformlyRandomElement()));
            }while (
                    messages[i].equals(wrongMessages[i])
            );
        }


        return new TrapdoorCommitmentTestParameters(pp, new MessageBlock(messages), new MessageBlock(wrongMessages), scheme, CommitmentKey);
    }

}
