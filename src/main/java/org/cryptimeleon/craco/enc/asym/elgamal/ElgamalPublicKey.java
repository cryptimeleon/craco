package org.cryptimeleon.craco.enc.asym.elgamal;

import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * An elgamal public key.
 *
 *
 */
public class ElgamalPublicKey implements EncryptionKey {
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
     * @param g      a generator
     * @param h      the public key h, where h := g^a (a is the private exponent)
     */
    public ElgamalPublicKey(GroupElement g, GroupElement h) {
        this.g = g;
        this.h = h;
    }

    public ElgamalPublicKey(Representation repr, Group group) {
        new ReprUtil(this).register(group, "groupG").deserialize(repr);
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
                && Objects.equals(h, other.h);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
