package org.cryptimeleon.craco.sig.sps.akot15.fsp2;

import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15OpenValue;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15Commitment;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignature;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representation;
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
        ObjectRepresentation objRepr = (ObjectRepresentation) repr;

        this.sigma_xsig = new SPSXSIGSignature(objRepr.get("sigma"), g1, g2);

        TCGAKOT15Commitment com = new TCGAKOT15Commitment(g2, objRepr.get("com"));
        TCAKOT15OpenValue open = new TCAKOT15OpenValue(g1, g2, objRepr.get("open"));

        this.commitmentPair_tc = new CommitmentPair(com, open);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation objRepr = new ObjectRepresentation();

        objRepr.put("sigma", sigma_xsig.getRepresentation());
        objRepr.put("com", commitmentPair_tc.getCommitment().getRepresentation());
        objRepr.put("open", commitmentPair_tc.getOpenValue().getRepresentation());

        return objRepr;
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
        if (!(o instanceof SPSFSP2Signature)) return false;
        SPSFSP2Signature that = (SPSFSP2Signature) o;
        return Objects.equals(sigma_xsig, that.sigma_xsig)
                && Objects.equals(commitmentPair_tc.getCommitment(), that.commitmentPair_tc.getCommitment())
                && Objects.equals(commitmentPair_tc.getOpenValue(), that.commitmentPair_tc.getOpenValue());
    }

    @Override
    public int hashCode() {
        return Objects.hash(sigma_xsig, commitmentPair_tc.getOpenValue(), commitmentPair_tc.getOpenValue());
    }

}
