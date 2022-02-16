package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

public class SPSXSIGVerificationKey implements VerificationKey {

    @Represented(restorer = "G2")
    protected GroupElement V1;

    @Represented(restorer = "G2")
    protected GroupElement V2;

    @Represented(restorer = "G2")
    protected GroupElement V3;

    @Represented(restorer = "G2")
    protected GroupElement V4;

    @Represented(restorer = "G2")
    protected GroupElement V5;

    @Represented(restorer = "G2")
    protected GroupElement V6;

    @Represented(restorer = "G1") //note: V7 is in Group G1
    protected GroupElement V7;

    @Represented(restorer = "G2")
    protected GroupElement V8;

    public SPSXSIGVerificationKey() { super(); }

    public SPSXSIGVerificationKey(GroupElement v1, GroupElement v2, GroupElement v3, GroupElement v4,
                                  GroupElement v5, GroupElement v6, GroupElement v7, GroupElement v8) {
        V1 = v1;
        V2 = v2;
        V3 = v3;
        V4 = v4;
        V5 = v5;
        V6 = v6;
        V7 = v7;
        V8 = v8;
    }

    public SPSXSIGVerificationKey(Group G1, Group G2, Representation repr){
        new ReprUtil(this).register(G1, "G1").register(G2, "G2").deserialize(repr);
    }




    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSXSIGVerificationKey that = (SPSXSIGVerificationKey) o;
        return Objects.equals(V1, that.V1) && Objects.equals(V2, that.V2) && Objects.equals(V3, that.V3) && Objects.equals(V4, that.V4) && Objects.equals(V5, that.V5) && Objects.equals(V6, that.V6) && Objects.equals(V7, that.V7) && Objects.equals(V8, that.V8);
    }

    @Override
    public int hashCode() {
        return Objects.hash(V1, V2, V3, V4, V5, V6, V7, V8);
    }

    public GroupElement getV1() {
        return V1;
    }

    public void setV1(GroupElement v1) {
        V1 = v1;
    }

    public GroupElement getV2() {
        return V2;
    }

    public void setV2(GroupElement v2) {
        V2 = v2;
    }

    public GroupElement getV3() {
        return V3;
    }

    public void setV3(GroupElement v3) {
        V3 = v3;
    }

    public GroupElement getV4() {
        return V4;
    }

    public void setV4(GroupElement v4) {
        V4 = v4;
    }

    public GroupElement getV5() {
        return V5;
    }

    public void setV5(GroupElement v5) {
        V5 = v5;
    }

    public GroupElement getV6() {
        return V6;
    }

    public void setV6(GroupElement v6) {
        V6 = v6;
    }

    public GroupElement getV7() {
        return V7;
    }

    public void setV7(GroupElement v7) {
        V7 = v7;
    }

    public GroupElement getV8() {
        return V8;
    }

    public void setV8(GroupElement v8) {
        V8 = v8;
    }
}
