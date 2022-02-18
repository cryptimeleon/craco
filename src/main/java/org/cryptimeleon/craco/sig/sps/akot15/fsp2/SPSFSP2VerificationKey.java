package org.cryptimeleon.craco.sig.sps.akot15.fsp2;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15CommitmentKey;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGVerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

public class SPSFSP2VerificationKey implements VerificationKey {

    @Represented
    protected SPSXSIGVerificationKey vk_xsig;

    @Represented
    protected TCGAKOT15CommitmentKey ck_tc;

    public SPSFSP2VerificationKey(SPSXSIGVerificationKey vk_xsig, TCGAKOT15CommitmentKey ck_tc) {
        this.vk_xsig = vk_xsig;
        this.ck_tc = ck_tc;
    }

    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }

    public SPSXSIGVerificationKey getVk_xsig() {
        return vk_xsig;
    }

    public TCGAKOT15CommitmentKey getCk_tc() {
        return ck_tc;
    }
}
