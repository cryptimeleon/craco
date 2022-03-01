package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the secret (signing) key of the KPW15 signature scheme.
 *
 */
public class SPSKPW15SigningKey implements SigningKey {

    // K, P0, P1, B

    /**
     * (n+1 x k+1) Matrix K in the paper
     * */
    @Represented(restorer = "[Zp]")
    protected Zp.ZpElement K[];

    /**
     * (k x k+1) Matrix P0 in the paper.
     * */
    @Represented(restorer = "[G1]")
    protected GroupElement P0[];

    /**
     * (k x k+1) Matrix P1 in the paper
     * */
    @Represented(restorer = "[G1]")
    protected GroupElement P1[];

    /**
     * B in the paper (note that since k = 1), B is just a single group element here
     * */
    @Represented(restorer = "G1")
    protected GroupElement B;


    public SPSKPW15SigningKey() { super(); }

    public SPSKPW15SigningKey(Representation representation, Zp zp, Group G_1) {
        new ReprUtil(this).register(zp, "Zp").register(G_1, "G1").deserialize(representation);
    }

    public SPSKPW15SigningKey(Zp.ZpElement[] K, GroupElement[] P0, GroupElement[] P1, GroupElement B){
        super();
        this.K = K;
        this.P0 = P0;
        this.P1 = P1;
        this.B = B;
    }

    public SPSKPW15SigningKey(Vector<Zp.ZpElement> K,
                              Vector<GroupElement> P0,
                              Vector<GroupElement> P1,
                              GroupElement B){

        this(
                K.stream().toArray(Zp.ZpElement[]::new),
                P0.stream().toArray(GroupElement[]::new),
                P1.stream().toArray(GroupElement[]::new),
                B
        );
    }

    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }


    public Zp.ZpElement[] getK() {
        return K;
    }

    public void setK(Zp.ZpElement[] K) {
        this.K = K;
    }

    public GroupElement[] getP0() {
        return P0;
    }

    public GroupElement[] getP1() {
        return P1;
    }

    public GroupElement getB() {
        return B;
    }

    public void setB(GroupElement B) {
        this.B = B;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SPSKPW15SigningKey)) return false;
        SPSKPW15SigningKey that = (SPSKPW15SigningKey) o;
        return Arrays.equals(K, that.K)
                && Arrays.equals(P0, that.P0)
                && Arrays.equals(P1, that.P1)
                && Objects.equals(B, that.B);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(B);
        result = 31 * result + Arrays.hashCode(K);
        result = 31 * result + Arrays.hashCode(P0);
        result = 31 * result + Arrays.hashCode(P1);
        return result;
    }

}
