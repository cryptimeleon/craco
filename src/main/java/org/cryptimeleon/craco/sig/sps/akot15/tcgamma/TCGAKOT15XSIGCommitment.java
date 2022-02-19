package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

/**
 * A variant of {@link TCGAKOT15Commitment} that is compatible with
 * the message space of {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}
 *
 */
public class TCGAKOT15XSIGCommitment extends TCGAKOT15Commitment{

    /**
     * G_u2 in G2 in the paper
     * */
    @Represented(restorer = "G2")
    private GroupElement group2ElementGu2;

    /**
     * G_u3 in G2 in the paper
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


    public MessageBlock toMessageBlock() {

        MessageBlock triple = new MessageBlock(new GroupElementPlainText(getGroup2ElementGu()),
                new GroupElementPlainText(group2ElementGu2),
                new GroupElementPlainText( group2ElementGu3));

        return new MessageBlock(new MessageBlock[] {triple});
    }

}
