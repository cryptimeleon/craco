package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.common.plaintexts.MessageBlock;
import de.upb.crypto.craco.common.plaintexts.RingElementPlainText;
import de.upb.crypto.craco.sig.SignatureKeyPair;
import de.upb.crypto.craco.sig.SignatureSchemeParams;

/**
 * Generates an instance of the {@link SignatureSchemeParams} for the {@link BBSBSignatureScheme}.
 */
public class BBSSignatureSchemeTestParamGenerator {
    public static SignatureSchemeParams generateParams(int securityParameter) {
        // setup
        BBSBKeyGen setup = new BBSBKeyGen();
        BBSBPublicParameter pp = setup.doKeyGen(securityParameter, true);
        BBSBSignatureScheme bbsScheme = new BBSBSignatureScheme(pp);

        // generate two different key pairs
        SignatureKeyPair<BBSBVerificationKey, BBSBSigningKey> keys = bbsScheme.generateKeyPair(2);
        SignatureKeyPair<BBSBVerificationKey, BBSBSigningKey> wrongKeys;
        do {
            wrongKeys = bbsScheme.generateKeyPair(2);
        } while (wrongKeys.equals(keys));

        // generate two different message blocks
        MessageBlock messageBlock = new MessageBlock(
                new RingElementPlainText(pp.getZp().getUniformlyRandomElement()),
                new RingElementPlainText(pp.getZp().getUniformlyRandomElement()));

        MessageBlock wrongMessageBlock;
        do {
            wrongMessageBlock = new MessageBlock(
                    new RingElementPlainText(pp.getZp().getUniformlyRandomElement()),
                    new RingElementPlainText(pp.getZp().getUniformlyRandomElement()));
        } while (wrongMessageBlock.equals(messageBlock));

        return new SignatureSchemeParams(bbsScheme, pp, messageBlock, wrongMessageBlock, keys, wrongKeys);
    }
}
