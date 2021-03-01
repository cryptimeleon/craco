package org.cryptimeleon.craco.secretsharing;

import org.cryptimeleon.craco.common.policies.Policy;

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
