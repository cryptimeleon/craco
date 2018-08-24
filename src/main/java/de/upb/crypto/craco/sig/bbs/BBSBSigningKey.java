package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Arrays;

/**
 * @author Fabian Eidens
 */
public class BBSBSigningKey implements SigningKey {
    private ZpElement exponentGamma; // gamma in the paper
    private ZpElement ziExponents[]; // g_1^{z_i} = h_i

    /**
     * Standard constructor
     */
    public BBSBSigningKey() {
        super();
    }

    public BBSBSigningKey(Representation repr, Zp zp) {
        RepresentationUtil.restoreElement(this, repr, "exponentGamma", zp);

        ListRepresentation listRepr = repr.obj().get("ziExponents").list();

        ziExponents = new ZpElement[listRepr.size()];
        for (int i = 0; i < listRepr.size(); i++) {
            ziExponents[i] = zp.getElement(listRepr.get(i));
        }
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
        ObjectRepresentation repr = new ObjectRepresentation();
        RepresentationUtil.putElement(this, repr, "exponentGamma");

        ListRepresentation listRep = new ListRepresentation();

        for (ZpElement zi : ziExponents) {
            listRep.put(zi.getRepresentation());
        }

        repr.put("ziExponents", listRep);

        return repr;
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
        if (exponentGamma == null) {
            if (other.exponentGamma != null)
                return false;
        } else if (!exponentGamma.equals(other.exponentGamma))
            return false;
        if (!Arrays.equals(ziExponents, other.ziExponents))
            return false;
        return true;
    }

}
