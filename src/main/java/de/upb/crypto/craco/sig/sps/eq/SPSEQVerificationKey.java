package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the public (verification) key of the SPS-EQ signature scheme.
 *
 * @author Fabian Eidens
 */

public class SPSEQVerificationKey implements VerificationKey {

    /**
     * \hat{X}_1, ..., \hat{X}_l \in G_2 in paper.
     */
    @RepresentedArray(elementRestorer = @Represented(structure = "groupG2", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    protected GroupElement[] group2ElementsHatXi;

    // pointer field used to store the structure for the representation process; in all other cases this should be null
    protected Group groupG2 = null;

    public SPSEQVerificationKey() {
        super();
    }

    public SPSEQVerificationKey(Group groupG2, Representation repr) {
        this.groupG2 = groupG2;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
        this.groupG2 = null;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public GroupElement[] getGroup2ElementsHatXi() {
        return group2ElementsHatXi;
    }

    public void setGroup2ElementsHatXi(GroupElement[] group2ElementsHatXi) {
        this.group2ElementsHatXi = group2ElementsHatXi;
    }

    public int getNumberOfMessages() {
        return group2ElementsHatXi.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSEQVerificationKey that = (SPSEQVerificationKey) o;
        return Arrays.equals(group2ElementsHatXi, that.group2ElementsHatXi);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(group2ElementsHatXi);
    }
}
