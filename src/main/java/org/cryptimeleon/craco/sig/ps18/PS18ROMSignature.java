package org.cryptimeleon.craco.sig.ps18;

import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * Class for a signature of the Pointcheval Sanders 2018 (Section 4.3) signature scheme
 * extended in the Random Oracle Model to reduce signature size.
 *
 *
 */
public class PS18ROMSignature implements Signature {
    /**
     * h in G_1^* in paper. Second element of signature.
     */
    @Represented(restorer = "G1")
    private GroupElement group1ElementSigma1;

    /**
     * h^{<sum here>} in G_1 in paper. Third element of signature.
     */
    @Represented(restorer = "G1")
    private GroupElement group1ElementSigma2;

    public PS18ROMSignature (GroupElement group1ElementSigma1,
                          GroupElement group1ElementSigma2) {
        this.group1ElementSigma1 = group1ElementSigma1;
        this.group1ElementSigma2 = group1ElementSigma2;
    }

    public PS18ROMSignature(Representation repr, Group groupG1) {
        new ReprUtil(this).register(groupG1, "G1")
                .deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getGroup1ElementSigma1() {
        return group1ElementSigma1;
    }

    public GroupElement getGroup1ElementSigma2() {
        return group1ElementSigma2;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PS18ROMSignature that = (PS18ROMSignature) o;
        return Objects.equals(group1ElementSigma1, that.group1ElementSigma1)
                && Objects.equals(group1ElementSigma2, that.group1ElementSigma2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group1ElementSigma1, group1ElementSigma2);
    }
}
