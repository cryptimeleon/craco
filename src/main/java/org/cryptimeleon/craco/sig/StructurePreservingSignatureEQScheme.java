package org.cryptimeleon.craco.sig;


import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.util.function.Function;

/**
 * A structure-preserving signature scheme on equivalence classes (SPS-EQ).
 * <p>
 * This is a special case of a multi-message signature scheme
 * because SPS-EQ additionally supports a change of the representative of the equivalence class that is signed.
 * <p>
 * See paper [1] for the definition of SPS-EQ.
 * <p>
 * [1] Georg Fuchsbauer and Christian Hanser and Daniel Slamanig, "Structure-Preserving Signatures on Equivalence Classes
 * and Constant-Size Anonymous Credentials", in Cryptology ePrint Archive, Report
 * 2014/944, 2014.
 */
public interface StructurePreservingSignatureEQScheme extends StandardMultiMessageSignatureScheme {

    /**
     * Returns a signature for the new representative computed based on the previous representative and the given
     * scalar {@code mu}.
     * <p>
     * If you have not yet verified the signature on the plaintext under the given verification key, use
     * {@link #chgRepWithVerify(PlainText, Signature, Zn.ZnElement, VerificationKey)} instead.
     * <p>
     * This method returns a signature matching the new representative of \([M]_R\), where \(M\) is the orignal plaintext.
     * The new representative of \([M]_R\) is supposed to be generated externally by using \(M\) and element \(\mu\).
     * The matching signature \(\sigma'\) for the new representative \(\mu \cdot M\) of \([M]_R\) is computed such that
     * {@code verify(M.pow(), sigma') == true}.
     * <p>
     * See paper [1] for details.
     *
     * @return a new valid signature on the new representative
     */
    Signature chgRep(Signature signature, Zn.ZnElement mu, VerificationKey publicKey);

    /**
     * Same as {@link #chgRep(Signature, Zn.ZnElement, VerificationKey)} but verifies the signature before
     * changing representative.
     *
     * @see #chgRep(Signature, Zn.ZnElement, VerificationKey)
     *
     * @return null if the given signature is not valid for {@code plainText} under {@code publicKey},
     * else a valid signature on the new representative
     */
    Signature chgRepWithVerify(PlainText plainText, Signature signature, Zn.ZnElement mu, VerificationKey publicKey);

    /**
     * Computes and returns the new representative computed based on the previous representative {@code plainText}
     * and the given scalar {@code mu}.
     */
    PlainText chgRepMessage(PlainText plainText, Zn.ZnElement mu);

    /**
     * Signs multiple group elements as a single unit.
     * @param secretKey key to sign with
     * @param groupElements group elements to sign
     * @return signature over the given plaintexts
     */
    default Signature sign(SigningKey secretKey, GroupElement... groupElements) {
        return sign(secretKey, new GroupElementVector(groupElements));
    }

    /**
     * Verifies a signature for multiple messages.
     * @param verificationKey key to use for verification
     * @param signature signature to verify
     * @param groupElements group elements to verify signature for
     * @return true if verification succeeds, else false
     */
    default Boolean verify(VerificationKey verificationKey, Signature signature, GroupElement... groupElements) {
        return verify(verificationKey, signature, new GroupElementVector(groupElements));
    }

    /**
     * Signs the given vector of group elements.
     * @param secretKey key to sign with
     * @param groupElements vector of group elements to sign
     * @return signature over the given vector of plaintexts
     */
    default Signature sign(SigningKey secretKey, GroupElementVector groupElements) {
        return sign(
                new MessageBlock(groupElements.map(
                        (Function<GroupElement, GroupElementPlainText>) GroupElementPlainText::new
                )),
                secretKey
        );
    }

    /**
     * Verifies a signature for a vector of group elements.
     * @param verificationKey key to use for verification
     * @param signature signature to verify
     * @param groupElements vector of group elements to verify signature for
     * @return true if verification succeeds, else false
     */
    default Boolean verify(VerificationKey verificationKey, Signature signature, GroupElementVector groupElements) {
        return verify(
                new MessageBlock(groupElements.map(
                        (Function<GroupElement, GroupElementPlainText>) GroupElementPlainText::new
                )),
                signature,
                verificationKey
        );
    }
}
