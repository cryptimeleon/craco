package org.cryptimeleon.craco.sig.sps.akot15.fsp2;

import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignature;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.structures.groups.Group;

import java.util.Objects;

public class SPSFSP2Signature implements Signature {

    SPSXSIGSignature sigma_xsig;

    CommitmentPair commitmentPair_tc;

    public SPSFSP2Signature(SPSXSIGSignature sigma_xsig, CommitmentPair commitmentPair_tc) {
        this.sigma_xsig = sigma_xsig;
        this.commitmentPair_tc = commitmentPair_tc;
    }

    public SPSFSP2Signature(Group g1, Group g2, Representation repr) {
        //this.sigma_xsig = new SPSXSIGSignature(repr, g1, g2);
        //this.commitmentPair_tc = new CommitmentPair();
    }

    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }

    public SPSXSIGSignature getSigma_xsig() {
        return sigma_xsig;
    }

    public CommitmentPair getCommitmentPair_tc() {
        return commitmentPair_tc;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSFSP2Signature that = (SPSFSP2Signature) o;
        return Objects.equals(sigma_xsig, that.sigma_xsig)
                && Objects.equals(commitmentPair_tc.getCommitment(), that.commitmentPair_tc.getCommitment())
                && Objects.equals(commitmentPair_tc.getOpenValue(), that.commitmentPair_tc.getOpenValue());
    }

    @Override
    public int hashCode() {
        return Objects.hash(sigma_xsig, commitmentPair_tc.getCommitment(), commitmentPair_tc.getOpenValue());
    }

}
