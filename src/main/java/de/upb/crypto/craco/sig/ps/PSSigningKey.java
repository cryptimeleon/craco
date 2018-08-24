package de.upb.crypto.craco.sig.ps;

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
 * Class for the secret (signing) key of the Pointcheval Sanders signature scheme.
 *
 * @author Fynn Dallmeier
 */

public class PSSigningKey implements SigningKey {

    /**
     * x \in Z_p in paper.
     */
    @Represented(structure = "zp", recoveryMethod = ZpElement.RECOVERY_METHOD)
    protected ZpElement exponentX;

    /**
     * y_1, ... , y_n \in Z_p in paper.
     */
    @RepresentedArray(elementRestorer = @Represented(structure = "zp", recoveryMethod = ZpElement.RECOVERY_METHOD))
    protected ZpElement exponentsYi[];

    // pointer field used to store the structure for the representation process; in all other cases this should be null
    protected Zp zp = null;

    public PSSigningKey() {
        super();
    }

    public PSSigningKey(Representation repr, Zp zp) {
        this.zp = zp;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
        this.zp = null;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public ZpElement getExponentX() {
        return exponentX;
    }

    public void setExponentX(ZpElement exponentX) {
        this.exponentX = exponentX;
    }

    public ZpElement[] getExponentsYi() {
        return exponentsYi;
    }

    public void setExponentsYi(ZpElement[] exponentsYi) {
        this.exponentsYi = exponentsYi;
    }

    public int getNumberOfMessages() {
        return exponentsYi.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSSigningKey that = (PSSigningKey) o;
        return Objects.equals(exponentX, that.exponentX) &&
                Arrays.equals(exponentsYi, that.exponentsYi);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(exponentX);
        result = 31 * result + Arrays.hashCode(exponentsYi);
        return result;
    }
}
