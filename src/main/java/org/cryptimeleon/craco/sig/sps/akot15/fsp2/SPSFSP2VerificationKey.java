package org.cryptimeleon.craco.sig.sps.akot15.fsp2;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15CommitmentKey;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15XSIGCommitmentKey;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGVerificationKey;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;

import java.util.Objects;

public class SPSFSP2VerificationKey implements VerificationKey {

    @Represented
    protected SPSXSIGVerificationKey vk_xsig;

    @Represented
    protected TCGAKOT15CommitmentKey ck_tc;

    public SPSFSP2VerificationKey(SPSXSIGVerificationKey vk_xsig, TCGAKOT15CommitmentKey ck_tc) {
        this.vk_xsig = vk_xsig;
        this.ck_tc = ck_tc;
    }

    public SPSFSP2VerificationKey(Group g1, Group g2, Representation repr) {

        ObjectRepresentation objRepr = (ObjectRepresentation) repr;

        this.vk_xsig = new SPSXSIGVerificationKey(g1,g2, objRepr.get("vkXSIG"));
        this.ck_tc = new TCGAKOT15XSIGCommitmentKey(g2, objRepr.get("ckTC"));
    }


    @Override
    public Representation getRepresentation() {

        ObjectRepresentation objRepr = new ObjectRepresentation();

        objRepr.put("vkXSIG", vk_xsig.getRepresentation());
        objRepr.put("ckTC", ck_tc.getRepresentation());

        return objRepr;
    }

    public SPSXSIGVerificationKey getVk_xsig() {
        return vk_xsig;
    }

    public TCGAKOT15CommitmentKey getCk_tc() {
        return ck_tc;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSFSP2VerificationKey that = (SPSFSP2VerificationKey) o;
        return Objects.equals(vk_xsig, that.vk_xsig) && Objects.equals(ck_tc, that.ck_tc);
    }

    @Override
    public int hashCode() {
        return Objects.hash(vk_xsig, ck_tc);
    }

}
