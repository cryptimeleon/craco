package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.sig.interfaces.VerificationKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

import java.util.Arrays;

/**
 * @author Fabian Eidens
 */
public class BBSBVerificationKey implements VerificationKey {
    private GroupElement w; // in G_2
    private GroupElement[] uiG2Elements; // u_i's in G_2

    public BBSBVerificationKey() {
        super();
    }

    public BBSBVerificationKey(Group groupG2, Representation repr) {
        ListRepresentation listRepr = repr.obj().get("uiG2Elements").list();

        uiG2Elements = new GroupElement[listRepr.size()];
        for (int i = 0; i < listRepr.size(); i++) {
            uiG2Elements[i] = groupG2.getElement(listRepr.get(i));
        }

        w = groupG2.getElement(repr.obj().get("w"));

    }

    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();

        RepresentationUtil.putElement(this, repr, "w");

        ListRepresentation listRep = new ListRepresentation();

        for (GroupElement ui : uiG2Elements) {
            listRep.put(ui.getRepresentation());
        }

        repr.put("uiG2Elements", listRep);

        return repr;
    }

    public GroupElement getW() {
        return w;
    }

    public void setW(GroupElement w) {
        this.w = w;
    }

    public GroupElement[] getUiG2Elements() {
        return uiG2Elements;
    }

    public void setUiG2Elements(GroupElement[] uiG2Elements) {
        this.uiG2Elements = uiG2Elements;
    }

    public int getNumberOfMessages() {
        return uiG2Elements.length - 1;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(uiG2Elements);
        result = prime * result + ((w == null) ? 0 : w.hashCode());
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
        BBSBVerificationKey other = (BBSBVerificationKey) obj;
        if (!Arrays.equals(uiG2Elements, other.uiG2Elements))
            return false;
        if (w == null) {
            if (other.w != null)
                return false;
        } else if (!w.equals(other.w))
            return false;
        return true;
    }

}
