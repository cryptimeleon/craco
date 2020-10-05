package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.sig.interfaces.VerificationKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Arrays;
import java.util.Objects;

/**
 * @author Fabian Eidens
 */
public class BBSBVerificationKey implements VerificationKey {
    @Represented(restorer = "G2")
    private GroupElement w; // in G_2
    @Represented(restorer = "[G2]")
    private GroupElement[] uiG2Elements; // u_i's in G_2

    public BBSBVerificationKey() {
        super();
    }

    public BBSBVerificationKey(Representation repr, Group groupG2) {
        new ReprUtil(this).register(groupG2, "G2").deserialize(repr);
    }

    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
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
        return Objects.equals(w, other.w)
                && Arrays.equals(uiG2Elements, other.uiG2Elements);
    }

}
