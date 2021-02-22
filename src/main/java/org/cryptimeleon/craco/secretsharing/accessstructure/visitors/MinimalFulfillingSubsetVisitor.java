package org.cryptimeleon.craco.secretsharing.accessstructure.visitors;

import org.cryptimeleon.craco.secretsharing.accessstructure.exceptions.WrongAccessStructureException;
import org.cryptimeleon.craco.secretsharing.accessstructure.utils.ComparablePair;
import org.cryptimeleon.craco.secretsharing.accessstructure.utils.LeafNode;
import org.cryptimeleon.craco.secretsharing.accessstructure.utils.TreeNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

/**
 * Given a set of shares (with identifiers between 0 and n-1 (inclusive)),
 * this visitor computes a minimal subset that can be used to reconstruct
 * a shared secret.
 */
public class MinimalFulfillingSubsetVisitor implements
        Visitor<ComparablePair<Integer, ArrayList<Integer>>> {

    /**
     * The set of party share identifiers that are used to check fulfillment of the access structure.
     * These are the shares that we have and want to compare against the shares required by the visited node.
     */
    private final Set<Integer> setOfShares;

    /**
     * Threshold of the node visited by this visitor.
     */
    private int threshold;

    /**
     * Specifies how many children of the current visited node are fulfilled.
     */
    private int numberOfFulfilledChildren = 0;

    /**
     * Contains pairs representing fulfilled children nodes of the current node.
     * First element of the pair specifies the number of fulfilled leaf nodes reachable from that child
     * (at most its threshold).
     * Second element contains identifiers of the fulfilled shares.
     */
    private final ArrayList<ComparablePair<Integer, ArrayList<Integer>>> fulfilledChildrenInfo;

    /**
     * Whether the threshold of the current node is reached (it is fulfilled).
     */
    private boolean fulfilled = false;

    /**
     * Whether we visited a leaf node.
     */
    private boolean leaf = false;

    /**
     * If this visitor is used to visit a leaf node, this is set to the share identifier of that leaf node.
     */
    private int leafNumber;

    public MinimalFulfillingSubsetVisitor(Set<Integer> setOfShareIdentifers) {
        this.setOfShares = setOfShareIdentifers;
        fulfilledChildrenInfo = new ArrayList<>();
    }

    /**
     * If the threshold of the visited node is fulfilled, this method computes
     * a pair containing the number of fulfilled leaf nodes reachable from the visited node
     * (at most the node's threshold), as well a {@link ArrayList} containing
     * the share identifiers of the fulfilled leaves.
     * This identifies a minimal subset of shares necessary to fulfill this node.
     */
    @Override
    public ComparablePair<Integer, ArrayList<Integer>> getResultOfCurrentNode() {
        if (fulfilled) {
            ArrayList<Integer> arraylist = new ArrayList<>();
            int minimalNumberOfFulfilledLeafs = 0;
            if (leaf) {
                // This node is a leaf, no need to do any deeper checks.
                arraylist.add(leafNumber);
                minimalNumberOfFulfilledLeafs = 1;
            } else {
                // Not a leaf node, check the current node's children for fulfillment.
                Integer counter = 0;

                Collections.sort(fulfilledChildrenInfo);

                for (ComparablePair<Integer, ArrayList<Integer>> entry : fulfilledChildrenInfo) {
                    counter++;
                    minimalNumberOfFulfilledLeafs = minimalNumberOfFulfilledLeafs
                            + entry.getFirst();
                    arraylist.addAll(entry.getSecond());

                    // Since we are interested in a minimal set of shares required to reconstruct the secret,
                    // we can stop once we reach the threshold.
                    if (counter.equals(threshold))
                        break;
                }
            }
            return new ComparablePair<>(
                    minimalNumberOfFulfilledLeafs, arraylist);
        } else {
            return new ComparablePair<>(0, null);
        }
    }

    @Override
    public MinimalFulfillingSubsetVisitor getVisitorForNextChild() {
        return new MinimalFulfillingSubsetVisitor(setOfShares);
    }

    /**
     * If the given result contains a fulfilled child, {@code numberOfFulfilledChildren} is incremented,
     * and, if the current node's threshold is reached, it is marked as fulfilled.
     * Furthermore, the result is added to {@code fulfilledChildrenInfo}.
     */
    @Override
    public void putResultOfChild(ComparablePair<Integer, ArrayList<Integer>> result) {
        if (!(result.getFirst() == 0)) {
            numberOfFulfilledChildren = numberOfFulfilledChildren + 1;
            if (numberOfFulfilledChildren == threshold)
                fulfilled = true;
            fulfilledChildrenInfo.add(result);
        }
    }

    /**
     * Sets {@code threshold} to the threshold of the given tree node.
     * If the given node is a leaf node (threshold is zero), this method additionally uses the set of share
     * identifiers specified in this {@link MinimalFulfillingSubsetVisitor} instance to check whether one of them
     * fulfills the share requirement of the given leaf node.
     *
     * @param currentNode The tree node to visit.
     * @throws WrongAccessStructureException if an inner node in the tree has threshold 0
     */
    @Override
    public void visit(TreeNode currentNode)
            throws WrongAccessStructureException {
        this.threshold = currentNode.getThreshold();

        if (threshold == 0) {
            if (currentNode instanceof LeafNode) {
                if (setOfShares.contains(((LeafNode) currentNode).getShareIdentifier())) {
                    leafNumber = ((LeafNode) currentNode).getShareIdentifier();
                    fulfilled = true;
                    leaf = true;
                }
            } else {
                throw new WrongAccessStructureException(
                        "Tree contains a node with children and Threshold 0. \n 0 is not a valid threshold.");
            }
        }
    }
}
