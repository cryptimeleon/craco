package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.sig.SigningKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;

/**
 * Class for the secret (signing) key of the SPS-EQ signature scheme.
 *
 * @author Fabian Eidens
 */

public class SPSEQSigningKey implements SigningKey {

    /**
     * x_1, ... , x_l \in Z_p^* in paper.
     */
    @Represented(restorer="[Zp]")
    protected ZpElement exponentsXi[];

    public SPSEQSigningKey() {
        super();
    }

    public SPSEQSigningKey(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
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
        return Arrays.hashCode(exponentsXi);
    }
}
