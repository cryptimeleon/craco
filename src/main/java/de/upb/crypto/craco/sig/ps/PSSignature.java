package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.sig.Signature;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * Class for a signature of the Pointcheval Sanders signature scheme.
 *
 *
 */

public class PSSignature implements Signature {

    /**
     * First group element of G_1 of the signature.
     */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementSigma1;

    /**
     * Second group element of G_1 of the signature, namely group1ElementSigma1^(x+\sum m_i*y_i).
     */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementSigma2;

    public PSSignature(Representation repr, Group groupG1) {
        new ReprUtil(this).register(groupG1, "G1").deserialize(repr);
    }

    public PSSignature(GroupElement group1ElementSigma1, GroupElement group1ElementSigma2) {
        super();
        this.group1ElementSigma1 = group1ElementSigma1;
        this.group1ElementSigma2 = group1ElementSigma2;
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
    public String toString() {
        return "PSSignature [sigma_1=" + group1ElementSigma1 + ", sigma_2=" + group1ElementSigma2 + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSSignature that = (PSSignature) o;
        return Objects.equals(group1ElementSigma1, that.group1ElementSigma1) &&
                Objects.equals(group1ElementSigma2, that.group1ElementSigma2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group1ElementSigma1, group1ElementSigma2);
    }
}
