package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Objects;

/**
 * Class for a signature of the Pointcheval Sanders 2018 (Section 4.2) signature scheme.
 *
 * @author Raphael Heitjohann
 */
public class PS18Signature implements Signature {

    /**
     * m' in Z_p in paper. First element of signature.
     */
    @Represented(restorer = "zp")
    private ZpElement exponentSigma1;

    /**
     * h in G_1^* in paper. Second element of signature.
     */
    @Represented(restorer = "G1")
    private GroupElement group1ElementSigma2;

    /**
     * h^{<sum here>} in G_1 in paper. Third element of signature.
     */
    @Represented(restorer = "G1")
    private GroupElement group1ElementSigma3;

    public PS18Signature (ZpElement exponentSigma1, GroupElement group1ElementSigma2,
                          GroupElement group1ElementSigma3) {
        super();
        this.exponentSigma1 = exponentSigma1;
        this.group1ElementSigma2 = group1ElementSigma2;
        this.group1ElementSigma3 = group1ElementSigma3;
    }

    public PS18Signature(Representation repr, Zp zp, Group groupG1) {
        new ReprUtil(this).register(zp, "zp").register(groupG1, "G1")
                .serialize();
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public ZpElement getExponentSigma1() { return exponentSigma1; }

    public void setExponentSigma1(ZpElement exponentSigma1) {
        this.exponentSigma1 = exponentSigma1;
    }

    public GroupElement getGroup1ElementSigma2() {
        return group1ElementSigma2;
    }

    public void setGroup1ElementSigma1(GroupElement group1ElementSigma2) {
        this.group1ElementSigma2 = group1ElementSigma2;
    }

    public GroupElement getGroup1ElementSigma3() {
        return group1ElementSigma3;
    }

    public void setGroup1ElementSigma3(GroupElement group1ElementSigma3) {
        this.group1ElementSigma3 = group1ElementSigma3;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PS18Signature that = (PS18Signature) o;
        return  Objects.equals(exponentSigma1, that.exponentSigma1)
                && Objects.equals(group1ElementSigma2, that.group1ElementSigma2)
                && Objects.equals(group1ElementSigma3, that.group1ElementSigma3);
    }

    @Override
    public int hashCode() {
        return Objects.hash(exponentSigma1, group1ElementSigma2, group1ElementSigma3);
    }
}
