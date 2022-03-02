package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;
import java.util.Objects;

public class SPSPOSVerificationKey implements VerificationKey {

    /**
     * G_i in group G_1 in the paper
     * */
    @Represented(restorer = "[G1]")
    protected GroupElement[] group1ElementsChi;

    /**
     * G_z in the paper
     * */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementW;

    /**
     * A in the paper
     * */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementA;

    private boolean isOTKeyValid;


    public SPSPOSVerificationKey() { super(); }

    public SPSPOSVerificationKey(GroupElement[] group1ElementsChi, GroupElement group1ElementW) {
        super();
        this.group1ElementsChi = group1ElementsChi;
        this.group1ElementW = group1ElementW;
        this.isOTKeyValid = false; // The one-time key has not been set yet, so it's not valid
    }

    public SPSPOSVerificationKey(Representation repr, Group G_1) {
        new ReprUtil(this).register(G_1, "G1").deserialize(repr);
    }




    public GroupElement[] getGroup1ElementsChi() {
        return group1ElementsChi;
    }

    public GroupElement getGroup1ElementW() {
        return group1ElementW;
    }

    public void SetOneTimeKey(GroupElement oneTimeKey) {
        this.group1ElementA = oneTimeKey;
        this.isOTKeyValid = true;
    }

    public GroupElement getAndUseOneTimeKey() {

        if(!isOTKeyValid){
            throw new IllegalStateException("This one-time key has already been used.");
        }

        isOTKeyValid = false;
        return this.group1ElementA;
    }

    public void setOneTimeKey(GroupElement oneTimeKey) {
        this.group1ElementA = oneTimeKey;
    }

    public GroupElement getOneTimeKey() {
        return this.group1ElementA;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSPOSVerificationKey that = (SPSPOSVerificationKey) o;
        return Arrays.equals(group1ElementsChi, that.group1ElementsChi)
                && Objects.equals(group1ElementW, that.group1ElementW);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(group1ElementW);
        result = 31 * result + Arrays.hashCode(group1ElementsChi);
        return result;
    }

}
