package org.cryptimeleon.craco.sig.sps.akot15.fsp2;

import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignature;
import org.cryptimeleon.math.serialization.Representation;

public class SPSFSP2Signature implements Signature {

    SPSXSIGSignature sigma_xsig;

    CommitmentPair commitmentPair_tc;

    public SPSFSP2Signature(SPSXSIGSignature sigma_xsig, CommitmentPair commitmentPair_tc) {
        this.sigma_xsig = sigma_xsig;
        this.commitmentPair_tc = commitmentPair_tc;
    }


    @Override
    public Representation getRepresentation() {
        return null;
    }

    public SPSXSIGSignature getSigma_xsig() {
        return sigma_xsig;
    }

    public CommitmentPair getCommitmentPair_tc() {
        return commitmentPair_tc;
    }
}
