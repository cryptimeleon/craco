package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * Class for a signature of the SPS-EQ signature scheme.
 *
 * @author Fabian Eidens
 */

public class SPSEQSignature implements Signature {

    /**
     * First group element of the signature in G_1.
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group1ElementSigma1Z;

    /**
     * Second group element of the signature in G_1.
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group1ElementSigma2Y;

    /**
     * Third group element of the signature in G_2.
     */
    @Represented(structure = "groupG2", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group1ElementSigma3HatY;


    // pointer fields used to store the structure for the representation process; in all other cases this should be null
    protected Group groupG1 = null;
    protected Group groupG2 = null;

    public SPSEQSignature(Representation repr, Group groupG1, Group groupG2) {
        this.groupG1 = groupG1;
        this.groupG2 = groupG2;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
        this.groupG1 = null;
        this.groupG2 = null;
    }

    public SPSEQSignature(GroupElement group1ElementSigma1Z, GroupElement group1ElementSigma2Y, GroupElement group1ElementSigma3HatY) {
        super();
        this.group1ElementSigma1Z = group1ElementSigma1Z;
        this.group1ElementSigma2Y = group1ElementSigma2Y;
        this.group1ElementSigma3HatY = group1ElementSigma3HatY;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public GroupElement getGroup1ElementSigma1Z() {
        return group1ElementSigma1Z;
    }

    public void setGroup1ElementSigma1Z(GroupElement group1ElementSigma1Z) {
        this.group1ElementSigma1Z = group1ElementSigma1Z;
    }

    public GroupElement getGroup1ElementSigma2Y() {
        return group1ElementSigma2Y;
    }

    public void setGroup1ElementSigma2Y(GroupElement group1ElementSigma2Y) {
        this.group1ElementSigma2Y = group1ElementSigma2Y;
    }

    public GroupElement getGroup1ElementSigma3HatY() {
        return group1ElementSigma3HatY;
    }

    public void setGroup1ElementSigma3HatY(GroupElement group1ElementSigma3HatY) {
        this.group1ElementSigma3HatY = group1ElementSigma3HatY;
    }

    @Override
    public String toString() {
        return "SPSEQSignature [sigma_1_Z=" + group1ElementSigma1Z + ", sigma_2_Y=" + group1ElementSigma2Y +  ", sigma_3_Hat_Y" + group1ElementSigma3HatY + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSEQSignature that = (SPSEQSignature) o;
        return Objects.equals(group1ElementSigma1Z, that.group1ElementSigma1Z) &&
                Objects.equals(group1ElementSigma2Y, that.group1ElementSigma2Y) &&
                Objects.equals(group1ElementSigma3HatY, that.group1ElementSigma3HatY);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group1ElementSigma1Z, group1ElementSigma2Y, group1ElementSigma3HatY);
    }
}
