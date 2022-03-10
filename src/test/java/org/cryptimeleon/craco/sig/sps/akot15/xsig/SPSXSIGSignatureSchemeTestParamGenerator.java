package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

public class SPSXSIGSignatureSchemeTestParamGenerator {

    public static SignatureSchemeParams generateParameters(int securityParameter, int numberOfMessageBlocks) {

        // setup scheme

        SPSXSIGPublicParameters pp = SPSXSIGPublicParametersGen.generatePublicParameters(
                securityParameter, numberOfMessageBlocks, true
        );

        SPSXSIGSignatureScheme scheme = new SPSXSIGSignatureScheme(pp);


        SignatureKeyPair<SPSXSIGVerificationKey, SPSXSIGSigningKey> keyPair = scheme.generateKeyPair(
                numberOfMessageBlocks);

        SignatureKeyPair<SPSXSIGVerificationKey, SPSXSIGSigningKey> wrongKeyPair;

        do{
            wrongKeyPair = scheme.generateKeyPair(numberOfMessageBlocks);
        }while(
                wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey())
        );

        // generate two different messages

        MessageBlock[] messageTriplets = new MessageBlock[numberOfMessageBlocks];

        for (int i = 0; i < messageTriplets.length; i++) {

            ZpElement mi = pp.getZp().getUniformlyRandomElement();

            GroupElementPlainText message1 = new GroupElementPlainText(pp.getGroup2ElementF1().pow(mi).compute());
            GroupElementPlainText message2 = new GroupElementPlainText(pp.getGroup2ElementF2().pow(mi).compute());
            GroupElementPlainText message3 = new GroupElementPlainText(pp.getGroup2ElementsU()[i].pow(mi).compute());

            messageTriplets[i] = new MessageBlock(message1, message2, message3);
        }

        MessageBlock[] wrongMessageTriplets = new MessageBlock[numberOfMessageBlocks];

        for (int i = 0; i < wrongMessageTriplets.length; i++) {

            do {
                ZpElement mi = pp.getZp().getUniformlyRandomElement();

                GroupElementPlainText message1 = new GroupElementPlainText(pp.getGroup2ElementF1().pow(mi).compute());
                GroupElementPlainText message2 = new GroupElementPlainText(pp.getGroup2ElementF2().pow(mi).compute());
                GroupElementPlainText message3 = new GroupElementPlainText(pp.getGroup2ElementsU()[i].pow(mi).compute());

                wrongMessageTriplets[i] = new MessageBlock(message1, message2, message3);

            }while(wrongMessageTriplets[i].equals(messageTriplets[i]));
        }

        return new SignatureSchemeParams(
                scheme,
                pp,
                new MessageBlock(messageTriplets),
                new MessageBlock(wrongMessageTriplets),
                keyPair,
                wrongKeyPair
        );
    }

}
