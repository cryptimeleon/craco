package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.util.RepresentationUtil;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * @author Fabian Eidens
 */
public class BBSBSigningKey implements SigningKey {
    @Represented(restorer = "Zp")
    private ZpElement exponentGamma; // gamma in the paper
    @Represented(restorer = "[Zp]")
    private ZpElement[] ziExponents; // g_1^{z_i} = h_i

    /**
     * Standard constructor
     */
    public BBSBSigningKey() {
        super();
    }

    public BBSBSigningKey(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }

    /**
     * Called gamma in the paper
     */
    public ZpElement getExponentGamma() {
        return exponentGamma;
    }

    /**
     * Called gamma in the paper
     */
    public void setExponentGamma(ZpElement exponentGamma) {
        this.exponentGamma = exponentGamma;
    }

    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public ZpElement[] getZiExponents() {
        return ziExponents;
    }

    public void setZiExponents(ZpElement[] ziExponents) {
        this.ziExponents = ziExponents;
    }

    public int getNumberOfMessages() {
        return ziExponents.length - 1;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((exponentGamma == null) ? 0 : exponentGamma.hashCode());
        result = prime * result + Arrays.hashCode(ziExponents);
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
        BBSBSigningKey other = (BBSBSigningKey) obj;
        return Objects.equals(exponentGamma, other.exponentGamma)
                && Arrays.equals(ziExponents, other.ziExponents);
    }

}
