package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * A variant of {@link TCGAKOT15Commitment} that is compatible with
 * the message space of {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}
 *
 * It adds two elements to the commitment which are required for XSIG to be able to sign this commitment.
 *
 */
public class TCGAKOT15XSIGCommitment extends TCGAKOT15Commitment{

    /**
     * G^{tilde}_u2 in G2 in the paper
     * */
    @Represented(restorer = "G2")
    private GroupElement group2ElementGu2;

    /**
     * G^{tilde}_u3 in G2 in the paper
     * */
    @Represented(restorer = "G2")
    private GroupElement group2ElementGu3;


    public TCGAKOT15XSIGCommitment(GroupElement group2ElementGu, GroupElement group2ElementGu2, GroupElement group2ElementGu3) {
        super(group2ElementGu);
        this.group2ElementGu2 = group2ElementGu2;
        this.group2ElementGu3 = group2ElementGu3;
    }

    public TCGAKOT15XSIGCommitment(Group group2, Representation repr) {
        super(group2, repr);
    }


    public GroupElement getGroup2ElementGu2() {
        return group2ElementGu2;
    }

    public GroupElement getGroup2ElementGu3() {
        return group2ElementGu3;
    }

    /**
     * generate a {@link MessageBlock} containing the {@link GroupElement}s stored in this commitment
     * in a way that they match the message structure required by
     * {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}
     * 
     */
    public MessageBlock toMessageBlock() {

        MessageBlock triple = new MessageBlock(new GroupElementPlainText(getGroup2ElementGu()),
                new GroupElementPlainText(group2ElementGu2),
                new GroupElementPlainText( group2ElementGu3));

        return new MessageBlock(new MessageBlock[] {triple});
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TCGAKOT15XSIGCommitment)) return false;
        if (!super.equals(o)) return false;
        TCGAKOT15XSIGCommitment that = (TCGAKOT15XSIGCommitment) o;
        return Objects.equals(group2ElementGu2, that.group2ElementGu2)
                && Objects.equals(group2ElementGu3, that.group2ElementGu3);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), group2ElementGu2, group2ElementGu3);
    }

}
