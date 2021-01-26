package de.upb.crypto.craco.secretsharing;

import de.upb.crypto.craco.secretsharing.policy.Policy;

/**
 * Interface for tree nodes used for {@link ThresholdTreeSecretSharing}.
 */
public interface SecretSharingTreeNode {

    /**
     * @return the number of children of the current node.
     */
    int getNumberOfChildren();

    /**
     * @return the number of shares in this node's subtree.
     */
    int getNumberOfShares();

    /**
     * @return the policy associated to the node.
     */
    Policy getPolicy();
}
