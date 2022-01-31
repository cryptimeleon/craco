package org.cryptimeleon.craco.sig;


import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;

import java.util.function.Function;

/**
 * Implements Structure Preserving Signature Schemes that operate on multiple Vectors of GroupElements at once
 */
public interface StandardMultiGroupMultiMessageStructurePreservingSignatureScheme
        extends MultiMessageStructurePreservingSignatureScheme{

    /**
     * Generates a key pair for signing n blocks of messages with {@code  messageBlockLengths}
     * with each signature.
     *
     * @param messageBlockLengths the length of the individual MessageBlocks this scheme accepts as input.
     */
    SignatureKeyPair<? extends  VerificationKey, ? extends  SigningKey> generateKeyPair(int... messageBlockLengths);


    /**
     * Signs the given vector of groupElementVectors.
     * @param secretKey key to sign with
     * @param groupElementVectors GroupElementVectors to sign
     * @return signature over the given vector of GroupElementVectors
     */
    default Signature sign(SigningKey secretKey, GroupElementVector... groupElementVectors) {
        return sign(secretKey, new Vector<GroupElementVector>(groupElementVectors));
    }


    /**
     * Signs the given vector of groupElementVectors.
     * @param secretKey key to sign with
     * @param groupElementVectors GroupElementVectors to sign
     * @param dummy due to issues with generic type erasure, this had to be added to the method in order to change its signature. The values of dummy do nothing
     * TODO refactor interface to avoid this issue
     * @return signature over the given vector of GroupElementVectors
     */
    default Signature sign(SigningKey secretKey, Vector<GroupElementVector> groupElementVectors, boolean... dummy) {

        MessageBlock containerBlock = new MessageBlock();

        for (int i = 0; i < groupElementVectors.length(); i++) {
            containerBlock.append(
                    new MessageBlock(
                        groupElementVectors.get(i).map(
                            (Function<GroupElement, GroupElementPlainText>) GroupElementPlainText::new)
                    )
            );
        }

        return sign(containerBlock, secretKey);
    }

    /**
     * Verifies a signature for a vector of GroupElementVectors.
     * @param publicKey key to use for verification
     * @param signature signature to verify
     * @param groupElementVectors vector of GroupElementVectors to verify signature for
     * @return true if verification succeeds, else false
     */
    default Boolean verify(VerificationKey publicKey, Signature signature, GroupElementVector... groupElementVectors) {
        return verify(publicKey, signature, new Vector<GroupElementVector>(groupElementVectors));
    }

    /**
     * Verifies a signature for a vector of GroupElementVectors.
     * @param publicKey key to use for verification
     * @param signature signature to verify
     * @param groupElementVectors vector of GroupElementVectors to verify signature for
     * @param dummy due to issues with generic type erasure, this had to be added to the method in order to change its signature. The values of dummy do nothing
     * TODO refactor interface to avoid this issue
     * @return true if verification succeeds, else false
     */
    default Boolean verify(VerificationKey publicKey, Signature signature, Vector<GroupElementVector> groupElementVectors, boolean... dummy) {

        MessageBlock containerBlock = new MessageBlock();

        for (int i = 0; i < groupElementVectors.length(); i++) {
            containerBlock.append(
                    new MessageBlock(
                        groupElementVectors.get(i).map(
                            (Function<GroupElement, GroupElementPlainText>) GroupElementPlainText::new)
                    )
            );
        }

        return verify(publicKey, signature, containerBlock);
    }

}
