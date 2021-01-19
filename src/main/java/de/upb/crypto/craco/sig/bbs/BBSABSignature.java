package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.sig.interfaces.Signature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zn.ZnElement;

import java.util.Objects;

/**
 * Class for a signature of the BBS-A and BBS-B signature scheme.
 *
 *
 */
public class BBSABSignature implements Signature {

    @Represented(restorer = "G1")
    private GroupElement elementA;
    
    @Represented(restorer = "Zp")
    private ZnElement exponentX, exponentS;

    /**
     * Restore the SignedMessage from Representation
     *
     * @param repr
     * @param groupG1
     */
    public BBSABSignature(Representation repr, Group groupG1) {
        new ReprUtil(this).register(groupG1, "G1").register(new Zn(groupG1.size()), "Zp").deserialize(repr);
    }

    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
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
        return Objects.equals(elementA, other.elementA)
                && Objects.equals(exponentS, other.exponentS)
                && Objects.equals(exponentX, other.exponentX);
    }

}
