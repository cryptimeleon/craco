package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.protocols.SecretInput;
import de.upb.crypto.craco.sig.SigningKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.cartesian.RingElementVector;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the secret (signing) key of the Pointcheval Sanders signature scheme.
 *
 *
 */

public class PSSigningKey implements SigningKey, SecretInput {

    /**
     * x \in Z_p in paper.
     */
    @Represented(restorer = "Zp")
    protected ZpElement exponentX;

    /**
     * y_1, ... , y_n \in Z_p in paper.
     */
    @Represented(restorer = "Zp")
    protected RingElementVector exponentsYi;

    public PSSigningKey(ZpElement exponentX, RingElementVector exponentsYi) {
        this.exponentX = exponentX;
        this.exponentsYi = exponentsYi;
    }

    public PSSigningKey(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public ZpElement getExponentX() {
        return exponentX;
    }

    public RingElementVector getExponentsYi() {
        return exponentsYi;
    }

    public int getNumberOfMessages() {
        return exponentsYi.length();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSSigningKey that = (PSSigningKey) o;
        return Objects.equals(exponentX, that.exponentX) &&
                exponentsYi.equals(that.exponentsYi);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(exponentX);
        result = 31 * result + exponentsYi.hashCode();
        return result;
    }
}
