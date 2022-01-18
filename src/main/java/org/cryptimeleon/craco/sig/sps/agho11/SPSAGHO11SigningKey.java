package org.cryptimeleon.craco.sig.sps.agho11;


import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the secret (signing) key of the AGHO11 signature scheme.
 *
 *
 */

public class SPSAGHO11SigningKey implements SigningKey {

    /**
     * u_1, ..., u_k_N in the paper
     */
    @Represented(restorer = "Zp")
    protected Zp.ZpElement exponentsU[];

    /**
     * v in the paper
     */
    @Represented(restorer = "Zp")
    protected Zp.ZpElement exponentV;

    /**
     * w_1, ..., w_k_M in the paper
     */
    @Represented(restorer = "Zp")
    protected Zp.ZpElement exponentsW[];

    /**
     * z in the paper
     */
    @Represented(restorer = "Zp")
    protected Zp.ZpElement exponentZ;




    public SPSAGHO11SigningKey() { super(); }

    public SPSAGHO11SigningKey(Representation representation, Zp zp){
        new ReprUtil(this).register(zp, "Zp").deserialize(representation);
    }

    public SPSAGHO11SigningKey(Zp.ZpElement[] exponentsU, Zp.ZpElement exponentV,
                               Zp.ZpElement[] exponentsW, Zp.ZpElement exponentZ){
        super();
        this.exponentsU = exponentsU;
        this.exponentV = exponentV;
        this.exponentsW = exponentsW;
        this.exponentZ = exponentZ;
    }



    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }




    public Zp.ZpElement[] getExponentsU() {
        return exponentsU;
    }

    public Zp.ZpElement getExponentV() {
        return exponentV;
    }

    public Zp.ZpElement[] getExponentsW() {
        return exponentsW;
    }

    public Zp.ZpElement getExponentZ() {
        return exponentZ;
    }


    public void setExponentsU(Zp.ZpElement[] exponentsU) {
        this.exponentsU = exponentsU;
    }

    public void setExponentV(Zp.ZpElement exponentV) {
        this.exponentV = exponentV;
    }

    public void setExponentsW(Zp.ZpElement[] exponentsW) {
        this.exponentsW = exponentsW;
    }

    public void setExponentZ(Zp.ZpElement exponentZ) {
        this.exponentZ = exponentZ;
    }




    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSAGHO11SigningKey that = (SPSAGHO11SigningKey) o;
        return Arrays.equals(exponentsU, that.exponentsU)
                &&  Objects.equals(exponentV, that.exponentV)
                &&  Arrays.equals(exponentsW, that.exponentsW)
                &&  Objects.equals(exponentZ, that.exponentZ);
    }

    @Override
    public int hashCode() {
        return Objects.hash(exponentsU, exponentV, exponentsW, exponentZ);
    }

}
