package de.upb.crypto.craco.enc.asym.elgamal;

import de.upb.crypto.craco.common.de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * An elgamal public key.
 *
 * @author Mirko Jürgens
 */
public class ElgamalPublicKey implements EncryptionKey {

    /**
     * The group of this Elgamal-Algorithm
     */
    @Represented
    private Group groupG;

    /**
     * The public parameter g \in groupG
     */
    @UniqueByteRepresented
    @Represented(restorer = "groupG")
    private GroupElement g;

    /**
     * The public parameter h:=g^a, (where a is the private key) \in groupG
     */
    @UniqueByteRepresented
    @Represented(restorer = "groupG")
    private GroupElement h;

    /**
     * Creates a new ElgamalPublic Key
     *
     * @param groupG the group
     * @param g      the generator of groupG
     * @param h      the public parameter h, where h := g^a (a is the private exponent)
     */
    public ElgamalPublicKey(Group groupG, GroupElement g, GroupElement h) {
        this.groupG = groupG;
        this.g = g;
        this.h = h;
    }

    public ElgamalPublicKey(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public void setGroupG(Group groupG) {
        this.groupG = groupG;
    }

    public Group getGroupG() {
        return groupG;
    }

    public GroupElement getG() {
        return g;
    }

    public GroupElement getH() {
        return h;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((groupG == null) ? 0 : groupG.hashCode());
        result = prime * result + ((h == null) ? 0 : h.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ElgamalPublicKey other = (ElgamalPublicKey) obj;
        return Objects.equals(g, other.g)
                && Objects.equals(groupG, other.groupG)
                && Objects.equals(h, other.h);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
