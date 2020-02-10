package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.sig.interfaces.Signature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * Class for a signature of the Pointcheval Sanders signature scheme.
 *
 * @author Fynn Dallmeier
 */

public class PSSignature implements Signature {

    /**
     * First group element of G_1 of the signature.
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group1ElementSigma1;

    /**
     * Second group element of G_1 of the signature, namely group1ElementSigma1^(x+\sum m_i*y_i).
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group1ElementSigma2;

    // pointer field used to store the structure for the representation process; in all other cases this should be null
    protected Group groupG1 = null;

    public PSSignature(Representation repr, Group groupG1) {
        this.groupG1 = groupG1;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
        this.groupG1 = null;
    }

    public PSSignature(GroupElement group1ElementSigma1, GroupElement group1ElementSigma2) {
        super();
        this.group1ElementSigma1 = group1ElementSigma1;
        this.group1ElementSigma2 = group1ElementSigma2;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public GroupElement getGroup1ElementSigma1() {
        return group1ElementSigma1;
    }

    public void setGroup1ElementSigma1(GroupElement group1ElementSigma1) {
        this.group1ElementSigma1 = group1ElementSigma1;
    }

    public GroupElement getGroup1ElementSigma2() {
        return group1ElementSigma2;
    }

    public void setGroup1ElementSigma2(GroupElement group1ElementSigma2) {
        this.group1ElementSigma2 = group1ElementSigma2;
    }

    @Override
    public String toString() {
        return "PSSignature [sigma_1=" + group1ElementSigma1 + ", sigma_2=" + group1ElementSigma2 + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSSignature that = (PSSignature) o;
        return Objects.equals(group1ElementSigma1, that.group1ElementSigma1) &&
                Objects.equals(group1ElementSigma2, that.group1ElementSigma2);
    }

    @Override
    public int hashCode() {

        return Objects.hash(group1ElementSigma1, group1ElementSigma2);
    }
}
