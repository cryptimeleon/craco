package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;

/**
 * A variant of {@link TCGAKOT15CommitmentKey} that is compatible with the message space
 * of {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}
 *
 */
public class TCGAKOT15XSIGCommitmentKey extends TCGAKOT15CommitmentKey{

    /**
     * X_i2 \in G2 in the paper
     * Defined as F^{tilde}_2^{rho_i}
     */
    @Represented(restorer = "[G2]")
    private GroupElement[] group2ElementsXi2;

    /**
     * X_i2 \in G2 in the paper
     * Defined as U^{tilde}_1^{rho_i}
     */
    @Represented(restorer = "[G2]")
    private GroupElement[] group2ElementsXi3;


    public TCGAKOT15XSIGCommitmentKey(GroupElement[] group2ElementsXi,
                                      GroupElement[] group2ElementsXi2,
                                      GroupElement[] group2ElementsXi3) {
        super(group2ElementsXi);
        this.group2ElementsXi2 = group2ElementsXi2;
        this.group2ElementsXi3 = group2ElementsXi3;
    }

    public TCGAKOT15XSIGCommitmentKey(Group group2, Representation repr) {
        super(group2, repr);
    }


    public GroupElement[] getGroup2ElementsXi2() {
        return group2ElementsXi2;
    }

    public GroupElement[] getGroup2ElementsXi3() {
        return group2ElementsXi3;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        TCGAKOT15XSIGCommitmentKey that = (TCGAKOT15XSIGCommitmentKey) o;
        return Arrays.equals(group2ElementsXi2, that.group2ElementsXi2)
                && Arrays.equals(group2ElementsXi3, that.group2ElementsXi3);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(group2ElementsXi2);
        result = 31 * result + Arrays.hashCode(group2ElementsXi3);
        return result;
    }
}
