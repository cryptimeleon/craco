package de.upb.crypto.craco.enc.asym.elgamal;

import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * The cipher text representation of an elgamal-encrypted plaintext.
 *
 * @author Mirko Jürgens
 */
public class ElgamalCipherText implements CipherText {
    /**
     * c1 := g^r
     */
    @Represented(restorer = "G")
    private GroupElement c1;
    /**
     * c2 := h^r *m
     */
    @Represented(restorer = "G")
    private GroupElement c2;

    /**
     * Creates a ciphertext object from the given representation of its elements and the specified group.
     *
     * @param repr the representation of c1 and c2
     * @param group          the group of the encryption
     */
    public ElgamalCipherText(Representation repr, Group group) {
        new ReprUtil(this).register(group, "G").deserialize(repr);
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
        return ReprUtil.serialize(this);
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
        return Objects.equals(c1, other.c1)
                && Objects.equals(c2, other.c2);
    }

    public GroupElement getC1() {
        return c1;
    }

    public GroupElement getC2() {
        return c2;
    }
}
