package de.upb.crypto.craco.enc.asym.elgamal;

import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

/**
 * The cipher text representation of an elgamal-encrypted plaintext.
 *
 * @author Mirko Jürgens
 */
public class ElgamalCipherText implements CipherText {
    /**
     * c1 := g^r
     */
    private GroupElement c1;
    /**
     * c2 := h^r *m
     */
    private GroupElement c2;

    /**
     * Creates a ciphertext object from the given representation of its elements and the specified group.
     *
     * @param representation the representation of c1 and c2
     * @param group          the group of the encryption
     */
    public ElgamalCipherText(Representation representation, Group group) {
        c1 = group.getElement(representation.obj().get("c1"));
        c2 = group.getElement(representation.obj().get("c2"));
    }

    /**
     * Creates a ciphertext object.
     *
     * @param c1 c1 := g^r
     * @param c2 c2 := h^r *m
     */
    public ElgamalCipherText(GroupElement c1, GroupElement c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation toReturn = new ObjectRepresentation();
        RepresentationUtil.putElement(this, toReturn, "c1");
        RepresentationUtil.putElement(this, toReturn, "c2");
        return toReturn;
    }

    @Override
    public String toString() {
        return "(" + c1.toString() + ", " + c2.toString() + ")";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((c1 == null) ? 0 : c1.hashCode());
        result = prime * result + ((c2 == null) ? 0 : c2.hashCode());
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
        ElgamalCipherText other = (ElgamalCipherText) obj;
        if (c1 == null) {
            if (other.c1 != null)
                return false;
        } else if (c2 == null) {
            if (other.c2 != null)
                return false;
        } else if (!c1.equals(other.c1))
            return false;
        else if (!c2.equals(other.c2))
            return false;
        return true;
    }

    public GroupElement getC1() {
        return c1;
    }

    public GroupElement getC2() {
        return c2;
    }
}
