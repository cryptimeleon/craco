package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

public class SPSPOSSigningKey implements SigningKey {

    /**
     * \chi_1, ... \chi_l in the paper
     * */
    @Represented(restorer = "[Zp]")
    protected ZpElement[] exponentsChi;

    /**
     * w_z in the paper
     * */
    @Represented(restorer = "Zp")
    protected ZpElement exponentW;

    /**
     * a in the paper
     * */
    @Represented(restorer = "Zp")
    protected ZpElement exponentA;

    private boolean isOTKeyValid;


    public SPSPOSSigningKey() { super(); }

    public SPSPOSSigningKey(ZpElement[] exponentsChi, ZpElement exponentW) {
        super();
        this.exponentsChi = exponentsChi;
        this.exponentW = exponentW;
        this.isOTKeyValid = false; // The one-time key has not been set yet, so it's not valid
    }

    public SPSPOSSigningKey(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }




    public ZpElement[] getExponentsChi() {
        return exponentsChi;
    }

    public ZpElement getExponentW() {
        return exponentW;
    }

    public void SetOneTimeKey(ZpElement oneTimeKey) {
        this.exponentA = oneTimeKey;
        this.isOTKeyValid = true;
    }

    public ZpElement GetAndUseOneTimeKey() {

        if(!isOTKeyValid) {
            throw new IllegalStateException("This one-time key has already been used.");
        }

        isOTKeyValid = false;
        return exponentA;
    }



    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSPOSSigningKey that = (SPSPOSSigningKey) o;
        return Arrays.equals(exponentsChi, that.exponentsChi) && Objects.equals(exponentW, that.exponentW);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(exponentW);
        result = 31 * result + Arrays.hashCode(exponentsChi);
        return result;
    }

}
