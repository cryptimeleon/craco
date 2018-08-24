package de.upb.crypto.craco.enc.asym.elgamal;

import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

/**
 * An elgamal public key.
 *
 * @author Mirko Jürgens
 */
public class ElgamalPublicKey implements EncryptionKey {

    /**The public paramter groupG, which specifies the group of g */
    //private final static String[] standaloneRepresentables = {"groupG"};

    /**
     * The public parameters in groupG (h := g^a, a is the private key)
     */
    private final static String[] elementRepresentablesG = {"g", "h"};

    /**
     * The group of this Elgamal-Algorithm
     */
    private Group groupG;

    /**
     * The public parameter g \in groupG
     */
    @UniqueByteRepresented
    private GroupElement g;

    /**
     * The public parameter h:=g^a, (where a is the private key) \in groupG
     */
    @UniqueByteRepresented
    private GroupElement h;

//	public ElgamalPublicKey (Representation representation){
//		RepresentationUtil.restoreStandaloneRepresentable(this, representation, "groupG");
//		g = groupG.getElement(representation.obj().get("g"));
//		h = groupG.getElement(representation.obj().get("h"));
//	}

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
        ObjectRepresentation toReturn = new ObjectRepresentation();
//		for (String standaloneRepresentable : standaloneRepresentables){
//			RepresentationUtil.putElement(this, toReturn, standaloneRepresentable);
//		}
        for (String elementRepresentable : elementRepresentablesG) {
            RepresentationUtil.putElement(this, toReturn, elementRepresentable);
        }
        return toReturn;
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
        if (g == null) {
            if (other.g != null)
                return false;
        } else if (!g.equals(other.g))
            return false;
        if (groupG == null) {
            if (other.groupG != null)
                return false;
        } else if (!groupG.equals(other.groupG))
            return false;
        if (h == null) {
            if (other.h != null)
                return false;
        } else if (!h.equals(other.h))
            return false;
        return true;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }


}
