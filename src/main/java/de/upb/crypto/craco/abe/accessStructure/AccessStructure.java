package de.upb.crypto.craco.abe.accessStructure;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.craco.abe.accessStructure.util.*;
import de.upb.crypto.craco.interfaces.abe.LinearSecretSharing;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This is an abstract implementation of LinearSecretSharing to
 * for schemes that are based on special threshold trees,
 * where leaf nodes correspond to shares. They are numbered 0,...,n-1.
 * An additional map associates a shareReceiver to each number/leaf.
 *
 * @author pschleiter, Fabian Eidens (refactor)
 */
public abstract class AccessStructure implements LinearSecretSharing<PolicyFact> {

    /**
     * the policy as a tree
     */
    protected TreeNode thresholdTree;

    /**
     * the field over that the shares of the secret and the constants of the
     * solving vector will be calculated
     */
    protected Zp field;

    /**
     * The map used for getShareReceiver(i) calls.
     */
    protected HashMap<Integer, PolicyFact> shareReceivers;

    /**
     * Constructs the access structure from 'policy' to share over 'field'.
     */
    public AccessStructure(Policy policy, Zp field) {
        this.field = field;
        PolicyToTreeNodeConverter converter = new PolicyToTreeNodeConverter(policy);
        shareReceivers = converter.getShareReceiverMap();
        thresholdTree = converter.getTree();
    }

    @Override
    public boolean isQualified(Set<? extends PolicyFact> setOfShareReceivers) throws WrongAccessStructureException {
        Set<Integer> shares = getSharesOfReceivers(setOfShareReceivers);
        Visitor<Boolean> visitor = new AccessGrantedVisitor(shares);
        thresholdTree.performVisitor(visitor);
        return visitor.getResultOfCurrentNode();
    }

    @Override
    public String toString() {
        ToStringVisitor visitor = new ToStringVisitor();
        try {
            thresholdTree.performVisitor(visitor);
            return visitor.getResultOfCurrentNode();
        } catch (WrongAccessStructureException e) {
            return super.toString();
        }

    }

    @Override
    public Map<Integer, PolicyFact> getShareReceiverMap() {
        return new HashMap<>(shareReceivers);
    }

    @Override
    public Zp getSharedRing() {
        return field;
    }
}
