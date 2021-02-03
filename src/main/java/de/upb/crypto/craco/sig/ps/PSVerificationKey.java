package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.sig.VerificationKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.cartesian.GroupElementVector;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the public (verification) key of the Pointcheval Sanders signature scheme.
 *
 *
 */

public class PSVerificationKey implements VerificationKey {

    /**
     * \tilde{g} \in G_2 in paper.
     */
    @Represented(restorer = "G2")
    protected GroupElement group2ElementTildeG;

    /**
     * \tilde{X} \in G_2 in paper.
     */
    @Represented(restorer = "G2")
    protected GroupElement group2ElementTildeX;

    /**
     * \tilde{Y}_1, ..., \tilde{Y}_n \in G_2 in paper.
     */
    @Represented(restorer = "G2")
    protected GroupElementVector group2ElementsTildeYi;

    public PSVerificationKey(GroupElement group2ElementTildeG, GroupElement group2ElementTildeX, GroupElementVector group2ElementsTildeYi) {
        this.group2ElementTildeG = group2ElementTildeG;
        this.group2ElementTildeX = group2ElementTildeX;
        this.group2ElementsTildeYi = group2ElementsTildeYi;
    }

    protected PSVerificationKey() {
        //Constructor to enable ReprUtil to do its work.
    }

    public PSVerificationKey(Group groupG2, Representation repr) {
        new ReprUtil(this).register(groupG2, "G2").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getGroup2ElementTildeG() {
        return group2ElementTildeG;
    }

    public GroupElement getGroup2ElementTildeX() {
        return group2ElementTildeX;
    }

    public GroupElementVector getGroup2ElementsTildeYi() {
        return group2ElementsTildeYi;
    }

    public int getNumberOfMessages() {
        return group2ElementsTildeYi.length();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSVerificationKey that = (PSVerificationKey) o;
        return Objects.equals(group2ElementTildeG, that.group2ElementTildeG) &&
                Objects.equals(group2ElementTildeX, that.group2ElementTildeX) &&
                Objects.equals(group2ElementsTildeYi, that.group2ElementsTildeYi);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group2ElementTildeX);
    }
}
