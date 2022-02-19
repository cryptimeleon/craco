package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

/**
 * A variant of {@link TCGAKOT15CommitmentKey} that is compatible with the message space
 * of {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}
 *
 */
public class TCGAKOT15XSIGCommitmentKey extends TCGAKOT15CommitmentKey{

    /**
     * X_i2 \in G2 in the paper
     * Defined as F^{tilde}_2^{pi}
     */
    @Represented(restorer = "[G2]")
    private GroupElement[] group2ElementsXi2;

    /**
     * X_i2 \in G2 in the paper
     * Defined as U^{tilde}_1^{pi}
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


    public MessageBlock toMessageBlock() {

        MessageBlock[] triples = new MessageBlock[getGroup2ElementsXi().length];

        for (int i = 0; i < getGroup2ElementsXi().length; i++) {

            MessageBlock triple = new MessageBlock(
                    new GroupElementPlainText(getGroup2ElementsXi()[i]),
                    new GroupElementPlainText(group2ElementsXi2[i]),
                    new GroupElementPlainText(group2ElementsXi3[i])
                    );

            triples[i] = triple;
        }

        return new MessageBlock(triples);
    }
}
