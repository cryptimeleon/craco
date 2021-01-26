package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.sig.Signature;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * Class for a signature of the Pointcheval Sanders 2018 (Section 4.3) signature scheme
 * extended in the Random Oracle Model to reduce signature size.
 *
 * @author Raphael Heitjohann
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

    public void setGroup1ElementSigma1(GroupElement group1ElementSigma1) {
        this.group1ElementSigma1 = group1ElementSigma1;
    }

    public GroupElement getGroup1ElementSigma2() {
        return group1ElementSigma2;
    }

    public void setGroup1ElementSigma2(GroupElement group1ElementSigma2) {
        this.group1ElementSigma2 = group1ElementSigma2;
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
