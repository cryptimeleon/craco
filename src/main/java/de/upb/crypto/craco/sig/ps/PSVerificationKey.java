package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class for the public (verification) key of the Pointcheval Sanders signature scheme.
 *
 * @author Fynn Dallmeier
 */

public class PSVerificationKey implements VerificationKey {

    /**
     * \tilde{g} \in G_2 in paper.
     */
    @Represented(structure = "groupG2", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group2ElementTildeG;

    /**
     * \tilde{X} \in G_2 in paper.
     */
    @Represented(structure = "groupG2", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement group2ElementTildeX;

    /**
     * \tilde{Y}_1, ..., \tilde{Y}_n \in G_2 in paper.
     */
    @RepresentedArray(elementRestorer = @Represented(structure = "groupG2", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    protected GroupElement[] group2ElementsTildeYi;

    // pointer field used to store the structure for the representation process; in all other cases this should be null
    protected Group groupG2 = null;

    public PSVerificationKey() {
        super();
    }

    public PSVerificationKey(Group groupG2, Representation repr) {
        this.groupG2 = groupG2;
        new ReprUtil(this).deserialize(repr);
        this.groupG2 = null;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getGroup2ElementTildeG() {
        return group2ElementTildeG;
    }

    public void setGroup2ElementTildeG(GroupElement group2ElementTildeG) {
        this.group2ElementTildeG = group2ElementTildeG;
    }

    public GroupElement getGroup2ElementTildeX() {
        return group2ElementTildeX;
    }

    public void setGroup2ElementTildeX(GroupElement group2ElementTildeX) {
        this.group2ElementTildeX = group2ElementTildeX;
    }

    public GroupElement[] getGroup2ElementsTildeYi() {
        return group2ElementsTildeYi;
    }

    public void setGroup2ElementsTildeYi(GroupElement[] group2ElementsTildeYi) {
        this.group2ElementsTildeYi = group2ElementsTildeYi;
    }

    public int getNumberOfMessages() {
        return group2ElementsTildeYi.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSVerificationKey that = (PSVerificationKey) o;
        return Objects.equals(group2ElementTildeG, that.group2ElementTildeG) &&
                Objects.equals(group2ElementTildeX, that.group2ElementTildeX) &&
                Arrays.equals(group2ElementsTildeYi, that.group2ElementsTildeYi);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(group2ElementTildeG, group2ElementTildeX);
        result = 31 * result + Arrays.hashCode(group2ElementsTildeYi);
        return result;
    }
}
