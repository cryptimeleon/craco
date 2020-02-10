package de.upb.crypto.craco.enc.asym.elgamal;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;

/**
 * An elgamal plaintext, which is an element of the specified group.
 *
 * @author Mirko Jürgens
 */
public class ElgamalPlainText implements PlainText, UniqueByteRepresentable {
    /**
     * The plaintext.
     */
    @UniqueByteRepresented
    private GroupElement plaintext;

    public ElgamalPlainText(Representation representation, Group group) {
        plaintext = group.getElement(representation);
    }

    public ElgamalPlainText(GroupElement plaintext) {
        this.plaintext = plaintext;
    }

    @Override
    public Representation getRepresentation() {
        return plaintext.getRepresentation();
    }

    @Override
    public String toString() {
        return plaintext.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((plaintext == null) ? 0 : plaintext.hashCode());
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
        ElgamalPlainText other = (ElgamalPlainText) obj;
        if (plaintext == null) {
            if (other.plaintext != null)
                return false;
        } else if (!plaintext.equals(other.plaintext))
            return false;
        return true;
    }

    public GroupElement getPlaintext() {
        return plaintext;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}
