package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the secret (signing) key of the SPS-EQ signature scheme.
 *
 * @author Fabian Eidens
 */

public class SPSEQSigningKey implements SigningKey {

    /**
     * x_1, ... , x_l \in Z_p^* in paper.
     */
    @RepresentedArray(elementRestorer = @Represented(structure = "zp", recoveryMethod = ZpElement.RECOVERY_METHOD))
    protected ZpElement exponentsXi[];

    // pointer field used to store the structure for the representation process; in all other cases this should be null
    protected Zp zp = null;

    public SPSEQSigningKey() {
        super();
    }

    public SPSEQSigningKey(Representation repr, Zp zp) {
        this.zp = zp;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
        this.zp = null;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public ZpElement[] getExponentsXi() {
        return exponentsXi;
    }

    public void setExponentsXi(ZpElement[] exponentsXi) {
        this.exponentsXi = exponentsXi;
    }

    public int getNumberOfMessages() {
        return exponentsXi.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSEQSigningKey that = (SPSEQSigningKey) o;
        return Arrays.equals(exponentsXi, that.exponentsXi);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(exponentsXi);
        return result;
    }
}
