package de.upb.crypto.craco.secretsharing.accessstructure;

import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.common.policies.PolicyFact;
import de.upb.crypto.craco.secretsharing.LinearSecretSharing;
import de.upb.crypto.craco.secretsharing.accessstructure.exceptions.WrongAccessStructureException;
import de.upb.crypto.craco.secretsharing.accessstructure.utils.PolicyToTreeNodeConverter;
import de.upb.crypto.craco.secretsharing.accessstructure.utils.TreeNode;
import de.upb.crypto.craco.secretsharing.accessstructure.visitors.AccessGrantedVisitor;
import de.upb.crypto.craco.secretsharing.accessstructure.visitors.ToStringVisitor;
import de.upb.crypto.craco.secretsharing.accessstructure.visitors.Visitor;
import de.upb.crypto.math.structures.rings.zn.Zp;

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
