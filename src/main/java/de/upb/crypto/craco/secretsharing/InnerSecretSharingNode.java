package de.upb.crypto.craco.secretsharing;

import de.upb.crypto.craco.secretsharing.policy.Policy;
import de.upb.crypto.craco.secretsharing.policy.ThresholdPolicy;

import java.util.List;
import java.util.Objects;

/**
 * An inner node in a tree of {@link ThresholdPolicy}s used by {@link ThresholdTreeSecretSharing}.
 */
public class InnerSecretSharingNode implements SecretSharingTreeNode {

    private List<SecretSharingTreeNode> children;
    private int numberOfShares;
    private ThresholdPolicy policy;
    private LinearSecretSharing<Policy> lsss;

    public InnerSecretSharingNode(List<SecretSharingTreeNode> children, int numberOfShares,
                                  ThresholdPolicy policy, LinearSecretSharing<Policy> lsss) {
        this.children = children;
        this.numberOfShares = numberOfShares;
        this.policy = policy;
        this.lsss = lsss;
    }

    @Override
    public int getNumberOfChildren() {
        return children.size();
    }

    @Override
    public int getNumberOfShares() {
        return numberOfShares;
    }

    @Override
    public ThresholdPolicy getPolicy() {
        return policy;
    }

    public List<SecretSharingTreeNode> getChildren() {
        return children;
    }

    public LinearSecretSharing<Policy> getLsss() {
        return lsss;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InnerSecretSharingNode that = (InnerSecretSharingNode) o;
        return numberOfShares == that.numberOfShares &&
                Objects.equals(children, that.children) &&
                Objects.equals(policy, that.policy) &&
                Objects.equals(lsss, that.lsss);
    }

    @Override
    public int hashCode() {
        return Objects.hash(children, numberOfShares, policy, lsss);
    }
}
