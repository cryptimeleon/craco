package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zn.ZnElement;

/**
 * Class for a signature of the BBS-A and BBS-B signature scheme.
 *
 * @author Fabian Eidens
 */
public class BBSABSignature implements Signature {

    private GroupElement elementA;
    private ZnElement exponentX, exponentS;

    private static final String[] group1Elements = {"elementA"};
    private static final String[] elementRepresentableExponents = {"exponentX", "exponentS"};

    /**
     * Restore the SignedMessage from Representation
     *
     * @param repr
     * @param gmpk
     */
    public BBSABSignature(Representation repr, Group groupG1) {
        for (String member : group1Elements) {
            RepresentationUtil.restoreElement(this, repr, member, groupG1);
        }

        Zn zp = new Zn(groupG1.size());

        for (String member : elementRepresentableExponents) {
            RepresentationUtil.restoreElement(this, repr, member, zp);
        }
    }

    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        for (String member : group1Elements) {
            RepresentationUtil.putElement(this, repr, member);
        }
        for (String member : elementRepresentableExponents) {
            RepresentationUtil.putElement(this, repr, member);
        }


        return repr;
    }

    /**
     * @param elementA
     * @param exponentX
     * @param exponentS
     */
    public BBSABSignature(GroupElement elementA, ZnElement exponentX, ZnElement exponentS) {
        super();
        this.elementA = elementA;
        this.exponentX = exponentX;
        this.exponentS = exponentS;
    }

    public GroupElement getElementA() {
        return elementA;
    }

    public void setElementA(GroupElement elementA) {
        this.elementA = elementA;
    }

    public ZnElement getExponentX() {
        return exponentX;
    }

    public void setExponentX(ZnElement exponentX) {
        this.exponentX = exponentX;
    }

    public ZnElement getExponentS() {
        return exponentS;
    }

    public void setExponentS(ZnElement exponentS) {
        this.exponentS = exponentS;
    }

    @Override
    public String toString() {
        return "BBSABSignature [elementA=" + elementA + ", exponentX=" + exponentX + ", exponentS=" + exponentS + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((elementA == null) ? 0 : elementA.hashCode());
        result = prime * result + ((exponentS == null) ? 0 : exponentS.hashCode());
        result = prime * result + ((exponentX == null) ? 0 : exponentX.hashCode());
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
        BBSABSignature other = (BBSABSignature) obj;
        if (elementA == null) {
            if (other.elementA != null)
                return false;
        } else if (!elementA.equals(other.elementA))
            return false;
        if (exponentS == null) {
            if (other.exponentS != null)
                return false;
        } else if (!exponentS.equals(other.exponentS))
            return false;
        if (exponentX == null) {
            if (other.exponentX != null)
                return false;
        } else if (!exponentX.equals(other.exponentX))
            return false;
        return true;
    }

}
