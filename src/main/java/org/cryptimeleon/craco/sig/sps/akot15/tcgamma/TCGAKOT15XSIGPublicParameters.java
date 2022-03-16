package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * The construction of the AKOT15 signature scheme FSPS2 requires the {@link PublicParameters} to match up
 * across building blocks.
 * This class extends these shared parameters with the elements required in TC_gamma's calculations if it is to be
 * combined with {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}
 *
 * This class represents a subset of {@link SPSXSIGPublicParameters}
 * One should only be able to instantiate this class using an existing instance of {@link SPSXSIGPublicParameters}.
 *
 * Note: The original paper contains a typo in the section: "Procedure: Matching C_gbc to M_xsig -- Setup" [1, p.17]
 *      The additional generators (F_2, U_1) must be \in G_2 in order for the calculations to work
 *
 */
public class TCGAKOT15XSIGPublicParameters extends AKOT15SharedPublicParameters {

    /**
     * F^{tilde}_2 \in G_2 in the paper
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementF2;

    /**
     * F^{tilde}_1 \in G_2 in the paper
     */
    @Represented(restorer = "bilinearGroup::getG2")
    protected GroupElement group2ElementU1;

    public TCGAKOT15XSIGPublicParameters(SPSXSIGPublicParameters xsigPublicParameters, int messageLength) {

        // set G,H^{tilde} as F_1, F^{tilde}_1 from xsigPublicParameters
        super(xsigPublicParameters.getBilinearGroup(), messageLength);

        this.group1ElementG = xsigPublicParameters.getGroup1ElementF1();
        this.group2ElementH = xsigPublicParameters.getGroup2ElementF1();

        // set additional parameters F^{tilde}_2, U^{tilde}_1

        this.group2ElementF2 = xsigPublicParameters.getGroup2ElementF2();
        this.group2ElementU1 = xsigPublicParameters.getGroup2ElementsU()[0];

        precompute();
    }

    public TCGAKOT15XSIGPublicParameters(Representation repr) {
        super(repr);
    }


    public GroupElement getGroup2ElementF2() {
        return group2ElementF2;
    }

    public GroupElement getGroup2ElementU1() {
        return group2ElementU1;
    }


    /**
     * precomputes the group elements of the public parameters.
     */
    private void precompute() {
        this.group2ElementF2.precomputePow();
        this.group2ElementU1.precomputePow();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TCGAKOT15XSIGPublicParameters)) return false;
        if (!super.equals(o)) return false;
        TCGAKOT15XSIGPublicParameters that = (TCGAKOT15XSIGPublicParameters) o;
        return Objects.equals(group2ElementF2, that.group2ElementF2)
                && Objects.equals(group2ElementU1, that.group2ElementU1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), group2ElementF2, group2ElementU1);
    }

}
