package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSPublicParametersGen;
import de.upb.crypto.math.structures.zn.Zp;

public class PS18SigSchemePerfTestParamGen {

    private PSPublicParameters pp;

    public PS18SigSchemePerfTestParamGen(int securityParam) {
        PSPublicParametersGen ppGen = new PSPublicParametersGen();
        this.pp = ppGen.generatePublicParameter(securityParam, true);
    }

    public PS18SignatureScheme generateSigScheme() {
        return new PS18SignatureScheme(pp);
    }

    public PS18SignatureSchemeExpr generateSigSchemeExpr() {
        return new PS18SignatureSchemeExpr(pp);
    }

    public MessageBlock generateMessage(int numMessages) {
        RingElementPlainText[] messages = new RingElementPlainText[numMessages];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new RingElementPlainText(pp.getZp().getUniformlyRandomElement());
        }
        return new MessageBlock(messages);
    }
}
