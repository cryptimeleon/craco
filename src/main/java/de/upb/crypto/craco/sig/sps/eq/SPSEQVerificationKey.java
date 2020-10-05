package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.sig.interfaces.VerificationKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Arrays;

/**
 * Class for the public (verification) key of the SPS-EQ signature scheme.
 *
 * @author Fabian Eidens
 */

public class SPSEQVerificationKey implements VerificationKey {

    /**
     * \hat{X}_1, ..., \hat{X}_l \in G_2 in paper.
     */
    @Represented(restorer = "[G2]")
    protected GroupElement[] group2ElementsHatXi;

    public SPSEQVerificationKey() {
        super();
    }

    public SPSEQVerificationKey(Group groupG2, Representation repr) {
        new ReprUtil(this).register(groupG2, "G2").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement[] getGroup2ElementsHatXi() {
        return group2ElementsHatXi;
    }

    public void setGroup2ElementsHatXi(GroupElement[] group2ElementsHatXi) {
        this.group2ElementsHatXi = group2ElementsHatXi;
    }

    public int getNumberOfMessages() {
        return group2ElementsHatXi.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSEQVerificationKey that = (SPSEQVerificationKey) o;
        return Arrays.equals(group2ElementsHatXi, that.group2ElementsHatXi);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(group2ElementsHatXi);
    }
}
