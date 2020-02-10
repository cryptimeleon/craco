package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.sig.interfaces.VerificationKey;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Objects;

/**
 * Extension of the verification key for a Pointcheval Sanders Signature Scheme to store the generator g and the
 * group-elements Y_i from group 1. These parameters are generated in the
 * doKeyGen((int numberOfMessages, PSPublicParameters p) method. The reason for storing those further variables is the
 * combined usage of the {@link PSExtendedSignatureScheme} with the
 * {@link PedersenCommitmentScheme} for being able blind and unblind messages before and after signing them. This is
 * achieved by using the same g and Y-i in the
 * {@link de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters} as provided by the
 * {@link PSExtendedSignatureScheme}. This case allows a user to receive a signature on a commitment for a message and
 * to then calculate the signature for the uncommited message and thereby receiving a signature of a signer for a
 * message without the signer knowing the content of the messaged.
 */
public class PSExtendedVerificationKey extends PSVerificationKey
        implements VerificationKey, UniqueByteRepresentable {

    // Added parameters to enable blindly signing messages in combination with the Pedersen commitment scheme
    // g for enabling optional blinding/unblinding
    @UniqueByteRepresented
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement group1ElementG;

    // Y_i for enabling optional blinding/unblinding
    @UniqueByteRepresented
    @RepresentedArray(elementRestorer = @Represented(structure = "groupG1", recoveryMethod = GroupElement
            .RECOVERY_METHOD))
    private GroupElement[] group1ElementsYi;

    // pointer field used to store the structure for the representation process; in all other cases this should be null
    private Group groupG1 = null;

    /**
     * Extended constructor for the extended verification key in the ACS allowing direct instantiation.
     *
     * @param group1Element         {@link GroupElement} g is a generator from {@link Group} 1
     * @param group1ElementsYi      {@link GroupElement[]} Y_i from {@link Group} 1
     * @param group2ElementTildeG   {@link GroupElement} g_Tilde is a generator from {@link Group} 2
     * @param group2ElementTildeX   {@link GroupElement} x_Tilde from {@link Group} 1
     * @param group2ElementsTildeYi {@link GroupElement[]} Y_i_Tilde from {@link Group} 2
     */
    public PSExtendedVerificationKey(GroupElement group1Element, GroupElement[] group1ElementsYi,
                                     GroupElement group2ElementTildeG, GroupElement group2ElementTildeX,
                                     GroupElement[] group2ElementsTildeYi) {
        super();
        setGroup1ElementG(group1Element);
        setGroup1ElementsYi(group1ElementsYi);
        setGroup2ElementTildeG(group2ElementTildeG);
        setGroup2ElementTildeX(group2ElementTildeX);
        setGroup2ElementsTildeYi(group2ElementsTildeYi);
    }

    /**
     * Extended constructor for the extended verification key in the ACS (from representation).
     *
     * @param groupG1 {@link Group} group 1 from {@link de.upb.crypto.math.interfaces.mappings.BilinearMap}
     * @param groupG2 {@link Group} group 2 from {@link de.upb.crypto.math.interfaces.mappings.BilinearMap}
     * @param repr    {@link Representation} of {@link PSExtendedVerificationKey}
     */
    public PSExtendedVerificationKey(Group groupG1, Group groupG2, Representation repr) {
        this.groupG1 = groupG1;
        this.groupG2 = groupG2;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
        this.groupG1 = null;
        this.groupG2 = null;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public GroupElement getGroup1ElementG() {
        return group1ElementG;
    }

    public void setGroup1ElementG(GroupElement group1ElementG) {
        this.group1ElementG = group1ElementG;
    }

    public GroupElement[] getGroup1ElementsYi() {
        return group1ElementsYi;
    }

    public void setGroup1ElementsYi(GroupElement[] group1ElementsYi) {
        this.group1ElementsYi = group1ElementsYi;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PSExtendedVerificationKey that = (PSExtendedVerificationKey) o;
        return Objects.equals(group1ElementG, that.group1ElementG) &&
                Arrays.equals(group1ElementsYi, that.group1ElementsYi);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), group1ElementG);
        result = 31 * result + Arrays.hashCode(group1ElementsYi);
        return result;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        return AnnotatedUbrUtil.autoAccumulate(byteAccumulator, this);
    }

    @Override
    public byte[] getUniqueByteRepresentation() {
        return this.updateAccumulator(new ByteArrayAccumulator()).extractBytes();
    }
}
