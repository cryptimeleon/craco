package org.cryptimeleon.craco.enc.asym.elgamal;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

/**
 * An elgamal plaintext, which is an element of the specified group.
 *
 *
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
        return Objects.equals(plaintext, other.plaintext);
    }

    public GroupElement getPlaintext() {
        return plaintext;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}