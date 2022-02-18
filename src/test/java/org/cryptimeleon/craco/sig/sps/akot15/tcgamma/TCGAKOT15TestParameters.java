package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.common.plaintexts.PlainText;

public class TCGAKOT15TestParameters {

    private PublicParameters publicParameters;
    private PlainText plainText;
    private PlainText wrongPlainText;
    private CommitmentScheme scheme;

    public TCGAKOT15TestParameters(PublicParameters publicParameters, PlainText plainText, PlainText wrongPlainText, CommitmentScheme scheme) {
        this.publicParameters = publicParameters;
        this.plainText = plainText;
        this.wrongPlainText = wrongPlainText;
        this.scheme = scheme;
    }


    public PublicParameters getPublicParameters() {
        return publicParameters;
    }

    public PlainText getPlainText() {
        return plainText;
    }

    public PlainText getWrongPlainText() {
        return wrongPlainText;
    }

    public CommitmentScheme getScheme() {
        return scheme;
    }


}
