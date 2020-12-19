package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.common.interfaces.policy.BooleanPolicy;
import de.upb.crypto.craco.common.interfaces.policy.BooleanPolicy.BooleanOperator;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * Takes a Policy and computes the internal tree used by the AccessStructure
 * class.
 *
 * @author Jan
 */
public class PolicyToTreeNodeConverter {
    private final HashMap<Integer, PolicyFact> shareReceivers;
    private final TreeNode tree;

    public PolicyToTreeNodeConverter(Policy policy) {
        shareReceivers = new HashMap<>();
        tree = policyToThresholdTree(policy);
    }

    public HashMap<Integer, PolicyFact> getShareReceiverMap() {
        return shareReceivers;
    }

    public TreeNode getTree() {
        return tree;
    }

    /**
     * Computes a threshold tree (TreeNode) from the policy. Populating
     * shareReceivers with the shareIdentifier -> shareReceiver map.
     */
    private TreeNode policyToThresholdTree(Policy policy) {
        if (policy == null)
            return null;

        if (policy instanceof PolicyFact) {
            int shareIdentifier =
                    shareReceivers.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1) + 1; // next
            // unused
            // identifier
            shareReceivers.put(shareIdentifier, (PolicyFact) policy);
            return new LeafNode(shareIdentifier);
        }

        if (policy instanceof ThresholdPolicy) {
            ArrayList<TreeNode> children = new ArrayList<>();
            for (Policy child : ((ThresholdPolicy) policy).getChildren()) {
                children.add(policyToThresholdTree(child));
            }
            return new InnerNode(children, ((ThresholdPolicy) policy).getThreshold());
        }

        if (policy instanceof BooleanPolicy) {
            BooleanPolicy booleanPolicy = (BooleanPolicy) policy;
            ArrayList<TreeNode> children = new ArrayList<>();
            for (Policy child : booleanPolicy.getChildren()) {
                children.add(policyToThresholdTree(child));
            }

            if (booleanPolicy.getOperator() == BooleanOperator.AND) {
                return new InnerNode(children, children.size());
            } else {
                return new InnerNode(children, 1);
            }
        }

        throw new IllegalArgumentException("unexpected type " + policy.getClass().getName() + " for policy");
    }
}
