package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.sig.interfaces.SigningKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.cartesian.RingElementVector;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * Secret (signing) key for the Pointcheval Sanders 2018 (Section 4.2) signature scheme.
 * @author Raphael Heitjohann
 */
public class PS18SigningKey implements SigningKey {

    /**
     * x \in Z_p in paper.
     */
    @Represented(restorer = "zp")
    private ZpElement exponentX;

    /**
     * y_1, ..., y_{r+1} in Z_p in paper.
     */
    @Represented(restorer = "zp")
    private RingElementVector exponentsYi;

    public PS18SigningKey(ZpElement exponentX, RingElementVector exponentsYi) {
        this.exponentX = exponentX;
        this.exponentsYi = exponentsYi;
    }

    /**
     * Constructs signing key from a representation and the finite field in
     * which exponentiation in the bilinear group is done.
     *
     * @param repr The representation to construct the signing key from.
     * @param zp Field with p equals the order of the bilinear group.
     */
    public PS18SigningKey(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "zp").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public ZpElement getExponentX() {
        return exponentX;
    }

    public void setExponentX(ZpElement exponentX) {
        this.exponentX = exponentX;
    }

    public RingElementVector getExponentsYi() {
        return exponentsYi;
    }

    public void setExponentsYi(RingElementVector exponentsYi) {
        this.exponentsYi = exponentsYi;
    }

    public int getNumberOfMessages() {
        // this scheme has one more y_i than the supported message length.
        return exponentsYi.length() - 1;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PS18SigningKey that = (PS18SigningKey) o;
        return Objects.equals(exponentX, that.exponentX)
                && Objects.equals(exponentsYi, that.exponentsYi);
    }

    @Override
    public int hashCode() {
        return Objects.hash(exponentX, exponentsYi);
    }
}
