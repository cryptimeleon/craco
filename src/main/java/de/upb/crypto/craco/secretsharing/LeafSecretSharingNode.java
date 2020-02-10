package de.upb.crypto.craco.secretsharing;

import de.upb.crypto.craco.common.interfaces.policy.Policy;

import java.util.Objects;

public class LeafSecretSharingNode implements SecretSharingTreeNode {

    private Policy policy;

    public LeafSecretSharingNode(Policy policy) {
        this.policy = policy;
    }

    @Override
    public int getNumberOfChildren() {
        return 0;
    }

    @Override
    public int getNumberOfShares() {
        return 1;
    }

    @Override
    public Policy getPolicy() {
        return policy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LeafSecretSharingNode that = (LeafSecretSharingNode) o;
        return Objects.equals(policy, that.policy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policy);
    }
}
