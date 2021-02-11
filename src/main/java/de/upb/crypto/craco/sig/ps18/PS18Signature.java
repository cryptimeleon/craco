package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.sig.Signature;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Objects;

/**
 * Class for a signature of the Pointcheval Sanders 2018 (Section 4.2) signature scheme.
 *
 *
 */
public class PS18Signature implements Signature {

    /**
     * m' in Z_p in paper. First element of signature.
     */
    @Represented(restorer = "zp")
    private ZpElement exponentPrimeM;

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

    public PS18Signature (ZpElement exponentPrimeM, GroupElement group1ElementSigma1,
                          GroupElement group1ElementSigma2) {
        this.exponentPrimeM = exponentPrimeM;
        this.group1ElementSigma1 = group1ElementSigma1;
        this.group1ElementSigma2 = group1ElementSigma2;
    }

    public PS18Signature(Representation repr, Zp zp, Group groupG1) {
        new ReprUtil(this).register(zp, "zp").register(groupG1, "G1")
                .deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public ZpElement getExponentPrimeM() { return exponentPrimeM; }

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
        PS18Signature that = (PS18Signature) o;
        return  Objects.equals(exponentPrimeM, that.exponentPrimeM)
                && Objects.equals(group1ElementSigma1, that.group1ElementSigma1)
                && Objects.equals(group1ElementSigma2, that.group1ElementSigma2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(exponentPrimeM, group1ElementSigma1, group1ElementSigma2);
    }
}
