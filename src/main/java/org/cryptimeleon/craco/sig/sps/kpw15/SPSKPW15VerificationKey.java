package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Arrays;
import java.util.Objects;

public class SPSKPW15VerificationKey implements VerificationKey {

    // C0, C1, C, A (all in G_2)

    /**
     * (k+1 x k) Matrix C0 in the paper
     * */
    @Represented(restorer = "[G2]")
    protected GroupElement C0[];

    /**
     * (k+1 x k) Matrix C1 in the paper
     * */
    @Represented(restorer = "[G2]")
    protected GroupElement C1[];

    /**
     * (n+1 x k) Matrix C in the paper
     * */
    @Represented(restorer = "[G2]")
    protected GroupElement C[];

    /**
     * A in the paper (note that since k = 1), A is just a single group element here
     * */
    @Represented(restorer = "G2")
    protected GroupElement A;




    public SPSKPW15VerificationKey() { super(); }

    public SPSKPW15VerificationKey(Group G_1, Group G_2, Representation repr) {
        new ReprUtil(this).register(G_1, "G1").register(G_2, "G2").deserialize(repr);
    }

    public SPSKPW15VerificationKey(Vector<GroupElement> C0,
                                   Vector<GroupElement> C1,
                                   Vector<GroupElement> C,
                                   GroupElement A) {
        this.C0 = (GroupElement[]) C0.stream().toArray();
        this.C1 = (GroupElement[]) C1.stream().toArray();
        this.C = (GroupElement[]) C.stream().toArray();
        this.A = A;
    }




    public GroupElement[] getC0() {
        return C0;
    }

    public void setC0(GroupElement[] c0) {
        C0 = c0;
    }

    public GroupElement[] getC1() {
        return C1;
    }

    public void setC1(GroupElement[] c1) {
        C1 = c1;
    }

    public GroupElement[] getC() {
        return C;
    }

    public void setC(GroupElement[] c) {
        C = c;
    }

    public GroupElement getA() {
        return A;
    }

    public void setA(GroupElement a) {
        A = a;
    }




    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public int hashCode() { return Objects.hash(C0,C1,C,A); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SPSKPW15VerificationKey that = (SPSKPW15VerificationKey) o;
        return Arrays.equals(C0, that.C0)
                && Arrays.equals(C1, that.C1)
                && Objects.equals(C, that.C)
                && Objects.equals(A, that.A);
    }

}
