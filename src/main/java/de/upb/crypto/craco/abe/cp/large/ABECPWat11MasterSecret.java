package de.upb.crypto.craco.abe.cp.large;

import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

/**
 * The MasterSecret for the {@link ABECPWat11} generated in the
 * {@link ABECPWat11Setup}
 *
 * @author Mirko Jürgens
 */
public class ABECPWat11MasterSecret implements MasterSecret {

    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g_y; // in G_1

    @SuppressWarnings("unused")
    private Group groupG1;

    public ABECPWat11MasterSecret(GroupElement g_y) {
        this.g_y = g_y;
    }

    public ABECPWat11MasterSecret(Group groupG1, Representation repr) {
        this.groupG1 = groupG1;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    public GroupElement get() {
        return g_y;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((g_y == null) ? 0 : g_y.hashCode());
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
        ABECPWat11MasterSecret other = (ABECPWat11MasterSecret) obj;
        if (g_y == null) {
            if (other.g_y != null)
                return false;
        } else if (!g_y.equals(other.g_y))
            return false;
        return true;
    }
}
