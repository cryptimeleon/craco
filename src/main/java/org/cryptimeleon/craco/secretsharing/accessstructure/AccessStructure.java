package org.cryptimeleon.craco.secretsharing.accessstructure;

import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.policies.PolicyFact;
import org.cryptimeleon.craco.secretsharing.LinearSecretSharing;
import org.cryptimeleon.craco.secretsharing.accessstructure.exceptions.WrongAccessStructureException;
import org.cryptimeleon.craco.secretsharing.accessstructure.utils.PolicyToTreeNodeConverter;
import org.cryptimeleon.craco.secretsharing.accessstructure.utils.TreeNode;
import org.cryptimeleon.craco.secretsharing.accessstructure.visitors.AccessGrantedVisitor;
import org.cryptimeleon.craco.secretsharing.accessstructure.visitors.ToStringVisitor;
import org.cryptimeleon.craco.secretsharing.accessstructure.visitors.Visitor;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This is an abstract implementation of {@link LinearSecretSharing}
 * for schemes that are based on special threshold trees,
 * where leaf nodes correspond to shares.
 * An additional map associates a share receiver to each number/leaf.
 *
 * @see LinearSecretSharing
 */
public abstract class AccessStructure implements LinearSecretSharing<PolicyFact> {

    /**
     * The root node of the threshold tree underlying this access structure.
     */
    protected TreeNode thresholdTree;

    /**
     * The field over which the shares of the secret and the constants of the
     * solving vector will be calculated.
     */
    protected Zp field;

    /**
     * Maps share indices to the share receivers they belong to.
     */
    protected HashMap<Integer, PolicyFact> shareReceivers;

    /**
     * Constructs the access structure from {@code policy} to share over {@code field}.
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
