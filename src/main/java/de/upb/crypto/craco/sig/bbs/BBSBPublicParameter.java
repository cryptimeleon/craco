package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.mappings.GroupHomomorphism;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;
import de.upb.crypto.math.structures.zn.HashIntoZn;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class BBSBPublicParameter implements PublicParameters {
    private Group groupG1, groupG2, groupGT;
    private BilinearMap bilinearMap; // G1 x G2 -> GT
    private HashIntoZn hashIntoZp; // byte[] -> Zp
    private GroupHomomorphism groupHom; // G2 -> G1 isomorphism
    private GroupElement g1; // in G1
    private GroupElement g2; // in G2

    public BBSBPublicParameter() {
        super();
    }

    private final static String[] standaloneRepresentables = new String[]{"groupG1", "groupG2", "groupGT",
            "bilinearMap", "hashIntoZp", "groupHom"};
    private static final String[] elementRepresentablesG1 = {"g1"};
    private static final String[] elementRepresentablesG2 = {"g2"};

    public BBSBPublicParameter(Representation repr) {
        for (String s : standaloneRepresentables) {
            RepresentationUtil.restoreStandaloneRepresentable(this, repr, s);
        }
        for (String s : elementRepresentablesG1) {
            RepresentationUtil.restoreElement(this, repr, s, groupG1);
        }
        for (String s : elementRepresentablesG2) {
            RepresentationUtil.restoreElement(this, repr, s, groupG2);
        }
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        for (String member : standaloneRepresentables) {
            RepresentationUtil.putStandaloneRepresentable(this, repr, member);
        }
        for (String member : elementRepresentablesG1) {
            RepresentationUtil.putElement(this, repr, member);
        }
        for (String member : elementRepresentablesG2) {
            RepresentationUtil.putElement(this, repr, member);
        }

        return repr;
    }

    public Group getGroupG1() {
        return groupG1;
    }

    public void setGroupG1(Group groupG1) {
        this.groupG1 = groupG1;
    }

    public Group getGroupG2() {
        return groupG2;
    }

    public void setGroupG2(Group groupG2) {
        this.groupG2 = groupG2;
    }

    public Group getGroupGT() {
        return groupGT;
    }

    public void setGroupGT(Group groupGT) {
        this.groupGT = groupGT;
    }

    public GroupHomomorphism getGroupHom() {
        return groupHom;
    }

    public void setGroupHom(GroupHomomorphism groupHom) {
        this.groupHom = groupHom;
    }

    public BilinearMap getBilinearMap() {
        return bilinearMap;
    }

    public void setBilinearMap(BilinearMap bilinearMap) {
        this.bilinearMap = bilinearMap;
    }

    public GroupElement getG1() {
        return g1;
    }

    public void setG1(GroupElement g1) {
        this.g1 = g1;
    }

    public GroupElement getG2() {
        return g2;
    }

    public void setG2(GroupElement g2) {
        this.g2 = g2;
    }

    /**
     * Returns the group Zp (where p is the group order of G1, G2, and GT)
     */
    public Zp getZp() {
        return new Zp(groupG1.size());
    }

    /**
     * Returns the group size of G1,G2, and GT
     */
    public BigInteger getGroupSize() {
        return groupG1.size();
    }

    public HashIntoZn getHashIntoZp() {
        return hashIntoZp;
    }

    public void setHashIntoZp(HashIntoZn hashIntoZp) {
        this.hashIntoZp = hashIntoZp;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((bilinearMap == null) ? 0 : bilinearMap.hashCode());
        result = prime * result + ((g1 == null) ? 0 : g1.hashCode());
        result = prime * result + ((g2 == null) ? 0 : g2.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupG2 == null) ? 0 : groupG2.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
        result = prime * result + ((groupHom == null) ? 0 : groupHom.hashCode());
        result = prime * result + ((hashIntoZp == null) ? 0 : hashIntoZp.hashCode());
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
        BBSBPublicParameter other = (BBSBPublicParameter) obj;
        if (bilinearMap == null) {
            if (other.bilinearMap != null)
                return false;
        } else if (!bilinearMap.equals(other.bilinearMap))
            return false;
        if (g1 == null) {
            if (other.g1 != null)
                return false;
        } else if (!g1.equals(other.g1))
            return false;
        if (g2 == null) {
            if (other.g2 != null)
                return false;
        } else if (!g2.equals(other.g2))
            return false;
        if (groupG1 == null) {
            if (other.groupG1 != null)
                return false;
        } else if (!groupG1.equals(other.groupG1))
            return false;
        if (groupG2 == null) {
            if (other.groupG2 != null)
                return false;
        } else if (!groupG2.equals(other.groupG2))
            return false;
        if (groupGT == null) {
            if (other.groupGT != null)
                return false;
        } else if (!groupGT.equals(other.groupGT))
            return false;
        if (groupHom == null) {
            if (other.groupHom != null)
                return false;
        } else if (!groupHom.equals(other.groupHom))
            return false;
        if (hashIntoZp == null) {
            if (other.hashIntoZp != null)
                return false;
        } else if (!hashIntoZp.equals(other.hashIntoZp))
            return false;
        return true;
    }


}
