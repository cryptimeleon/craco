package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.sps.CommitmentSchemeParams;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParametersGen;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class TCGAKOT15CommitmentSchemeTestParameterGenerator {

    public static CommitmentSchemeParams generateParameters(int securityParameter, int messageLength) {

        AKOT15SharedPublicParameters pp = AKOT15SharedPublicParametersGen.generateParameters(securityParameter, messageLength, true);

        TCGAKOT15CommitmentScheme scheme = new TCGAKOT15CommitmentScheme(pp);

        //generate messages

        RingElementPlainText[] messages = new RingElementPlainText[messageLength];

        Zp zp = pp.getZp();

        for (int i = 0; i < messageLength; i++) {
            messages[i] = new RingElementPlainText(zp.getUniformlyRandomElement());
        }

        RingElementPlainText[] wrongMessages = new RingElementPlainText[messageLength];

        for (int i = 0; i < messageLength; i++) {

            do {
                wrongMessages[i] = new RingElementPlainText(zp.getUniformlyRandomElement());
            }while (
                    messages[i].equals(wrongMessages[i])
            );
        }


        return new CommitmentSchemeParams(pp, new MessageBlock(messages), new MessageBlock(wrongMessages), scheme, scheme.getCommitmentKey());
    }

}
