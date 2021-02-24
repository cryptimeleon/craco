package org.cryptimeleon.craco.sig.sps.eq;

import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;

/**
 * Class for the secret (signing) key of the SPS-EQ signature scheme.
 *
 *
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
