package org.cryptimeleon.craco.sig;


import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.util.function.Function;

/**
 * A structure-preserving signature scheme
 * <p>
 * This is a special case of a multi-message signature scheme
 * because SPS supports signing group elements
 * <p>
 * See paper [1] for the definition of SPS.
 * <p>
 * [1] Abe, Masayuki and Fuchsbauer, Georg and Groth, Jens and Haralambiev, Kristiyan and Ohkubo, Miyako
 * "Structure-preserving signatures and commitments to group elements", in CRYPTO 2010,
 * https://www.iacr.org/archive/crypto2010/62230210/62230210.pdf, 2010.
 */
public interface MultiMessageStructurePreservingSignatureScheme extends StandardMultiMessageSignatureScheme {

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
