package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.CommitmentKey;
import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.common.plaintexts.PlainText;

/**
 * Parameter for a commitment scheme test.
 */
public class TrapdoorCommitmentTestParameters {

    private PublicParameters publicParameters;
    private PlainText plainText;
    private PlainText wrongPlainText;
    private CommitmentScheme scheme;
    private CommitmentKey commitmentKey;

    public TrapdoorCommitmentTestParameters(PublicParameters publicParameters, PlainText plainText, PlainText wrongPlainText, CommitmentScheme scheme, CommitmentKey commitmentKey) {
        this.publicParameters = publicParameters;
        this.plainText = plainText;
        this.wrongPlainText = wrongPlainText;
        this.scheme = scheme;
        this.commitmentKey = commitmentKey;
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

    public CommitmentKey getCommitmentKey() {
        return commitmentKey;
    }

}
