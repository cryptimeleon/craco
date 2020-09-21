package de.upb.crypto.craco.enc.asym.elgamal;

import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

import java.util.Objects;

/**
 * An elgamal public key.
 *
 * @author Mirko Jürgens
 */
public class ElgamalPublicKey implements EncryptionKey {

    /**
     * The public parameter g \in groupG
     */
    @UniqueByteRepresented
    @Represented(restorer = "G")
    private GroupElement g;

    /**
     * The public parameter h:=g^a, (where a is the private key) \in groupG
     */
    @UniqueByteRepresented
    @Represented(restorer = "G")
    private GroupElement h;

    /**
     * Creates a new ElgamalPublic Key

     * @param g      the generator of groupG
     * @param h      the public parameter h, where h := g^a (a is the private exponent)
     */
    public ElgamalPublicKey(GroupElement g, GroupElement h) {
        this.g = g;
        this.h = h;
    }

    public ElgamalPublicKey(Representation repr, Group groupG) {
        new ReprUtil(this).register(groupG, "G").deserialize(repr);
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
