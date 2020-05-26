package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.math.pairings.debug.DebugBilinearMap;
import de.upb.crypto.math.pairings.debug.DebugGroupLogger;

/**
 * Generates an instance of the {@link SignatureSchemeParams} for the {@link SPSEQSignatureScheme}.
 */
public class SPSEQSignatureSchemeTestParamGenerator {
    static long timerStart = 0;

    public static SignatureSchemeParams generateParams(int securityParam, int numMessages) {
        // setup scheme
        measureTime(null);
        SPSEQPublicParametersGen ppSetup = new SPSEQPublicParametersGen();
        SPSEQPublicParameters pp = ppSetup.generatePublicParameter(securityParam, false);
        measureTime("Setup");
        SPSEQSignatureScheme spseqScheme = new SPSEQSignatureScheme(pp);

        // generate two different key pairs to test
        measureTime(null);
        SignatureKeyPair<? extends SPSEQVerificationKey, ? extends SPSEQSigningKey> keyPair = spseqScheme.generateKeyPair(
                numMessages);
        measureTime("KeyGen");
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


    protected static void measureTime(String str) {
        if (timerStart == 0) {
            DebugGroupLogger.reset();
            timerStart = System.currentTimeMillis();
        } else {
            long end = System.currentTimeMillis();
            System.out.println(str + ": " + ((end - timerStart) / 1000) + "s, " + ((end - timerStart) % 1000) + "ms");
            timerStart = 0;
        }
    }
}
