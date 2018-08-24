package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.abe.cp.small.ABECPWat11SmallSetup;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.MapRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * The parameters for the {@link ABEKPGPSW06Small} generated in the
 * {@link ABECPWat11SmallSetup}.
 *
 * @author Mirko Jürgens
 */
public class ABEKPGPSW06SmallPublicParameters implements PublicParameters {

    /**
     * For representation purposes
     */
    private final static String[] standaloneRepresentables = new String[]{"groupG1", "groupGT", "e"};
    private final static String[] elementRepresentablesG1 = new String[]{"g"};
    private final static String[] elementRepresentablesGT = new String[]{"Y"};

    // in groupG1
    private GroupElement g;
    // Attribute in universe T_i in groupG1
    private Map<Attribute, GroupElement> T;
    // in groupGT
    private GroupElement Y;

    private Group groupG1, groupGT;

    private BilinearMap e;

    public ABEKPGPSW06SmallPublicParameters() {
    }

    public ABEKPGPSW06SmallPublicParameters(Representation repr) {
        for (String s : standaloneRepresentables) {
            RepresentationUtil.restoreStandaloneRepresentable(this, repr, s);
        }
        for (String s : elementRepresentablesG1) {
            RepresentationUtil.restoreElement(this, repr, s, groupG1);
        }
        for (String s : elementRepresentablesGT) {
            RepresentationUtil.restoreElement(this, repr, s, groupGT);
        }

        T = new HashMap<Attribute, GroupElement>();
        repr.obj().get("T").map().forEach(entry -> T.put((Attribute) entry.getKey().repr().recreateRepresentable(),
                groupG1.getElement(entry.getValue())));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        for (String s : standaloneRepresentables) {
            RepresentationUtil.putStandaloneRepresentable(this, repr, s);
        }
        for (String s : elementRepresentablesG1) {
            RepresentationUtil.putElement(this, repr, s);
        }
        for (String s : elementRepresentablesGT) {
            RepresentationUtil.putElement(this, repr, s);
        }
        MapRepresentation map = new MapRepresentation();
        T.forEach((a, g) -> map.put(new RepresentableRepresentation(a), g.getRepresentation()));
        repr.put("T", map);

        return repr;
    }

    public GroupElement getG() {
        return g;
    }

    public void setG(GroupElement g) {
        this.g = g;
    }

    public Map<Attribute, GroupElement> getT() {
        return T;
    }

    public void setT(Map<Attribute, GroupElement> t) {
        T = t;
    }

    public GroupElement getY() {
        return Y;
    }

    public void setY(GroupElement y) {
        Y = y;
    }

    public Group getGroupG1() {
        return groupG1;
    }

    public void setGroupG1(Group groupG1) {
        this.groupG1 = groupG1;
    }

    public Group getGroupGT() {
        return groupGT;
    }

    public void setGroupGT(Group groupGT) {
        this.groupGT = groupGT;
    }

    public BilinearMap getE() {
        return e;
    }

    public void setE(BilinearMap e) {
        this.e = e;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABEKPGPSW06SmallPublicParameters other = (ABEKPGPSW06SmallPublicParameters) obj;
        if (T == null) {
            if (other.T != null)
                return false;
        } else if (!T.equals(other.T))
            return false;
        if (Y == null) {
            if (other.Y != null)
                return false;
        } else if (!Y.equals(other.Y))
            return false;
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (g == null) {
            if (other.g != null)
                return false;
        } else if (!g.equals(other.g))
            return false;
        if (groupG1 == null) {
            if (other.groupG1 != null)
                return false;
        } else if (!groupG1.equals(other.groupG1))
            return false;
        if (groupGT == null) {
            if (other.groupGT != null)
                return false;
        } else if (!groupGT.equals(other.groupGT))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((T == null) ? 0 : T.hashCode());
        result = prime * result + ((Y == null) ? 0 : Y.hashCode());
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        result = prime * result + ((groupG1 == null) ? 0 : groupG1.hashCode());
        result = prime * result + ((groupGT == null) ? 0 : groupGT.hashCode());
        return result;
    }
}
