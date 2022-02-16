package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

public class SPSXSIGSigningKey implements SigningKey {

    @Represented(restorer = "G1")
    protected GroupElement K1;

    @Represented(restorer = "G1")
    protected GroupElement K2;

    @Represented(restorer = "G1")
    protected GroupElement K3;

    @Represented(restorer = "G1")
    protected GroupElement K4;

    //V6 is part of the verification key, but it is used for signature calculation
    @Represented(restorer = "G2")
    protected GroupElement V6;

    //TODO Move elements to array to cut down on getter/setter clutter

    public SPSXSIGSigningKey() { super(); }

    public SPSXSIGSigningKey(GroupElement V6, GroupElement K1, GroupElement K2, GroupElement K3, GroupElement K4) {
        this.K1 = K1;
        this.K2 = K2;
        this.K3 = K3;
        this.K4 = K4;
        this.V6 = V6;
    }

    public SPSXSIGSigningKey(Group G1, Group G2, Representation repr){
        new ReprUtil(this).register(G1, "G1").register(G2, "G2").deserialize(repr);
    }




    public GroupElement getK1() {
        return K1;
    }

    public void setK1(GroupElement k1) {
        K1 = k1;
    }

    public GroupElement getK2() {
        return K2;
    }

    public void setK2(GroupElement k2) {
        K2 = k2;
    }

    public GroupElement getK3() {
        return K3;
    }

    public void setK3(GroupElement k3) {
        K3 = k3;
    }

    public GroupElement getK4() {
        return K4;
    }

    public void setK4(GroupElement k4) {
        K4 = k4;
    }

    public GroupElement getV6() {
        return V6;
    }

    public void setV6(GroupElement v6) {
        V6 = v6;
    }


    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSXSIGSigningKey that = (SPSXSIGSigningKey) o;
        return Objects.equals(K1, that.K1) && Objects.equals(K2, that.K2) && Objects.equals(K3, that.K3) && Objects.equals(K4, that.K4);
    }

    @Override
    public int hashCode() {
        return Objects.hash(K1, K2, K3, K4);
    }


}
