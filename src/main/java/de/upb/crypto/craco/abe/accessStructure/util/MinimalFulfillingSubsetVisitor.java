package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

/**
 * Given a set of shares (with identifiers 0,...,n-1),
 * computes a minimal subset that can be used to reconstruct
 * a shared secret.
 */
public class MinimalFulfillingSubsetVisitor implements
        Visitor<Pair<Integer, ArrayList<Integer>>> {

    /**
     * the set of parties for that it will be checked whether they fulfill the
     * access structure or not
     */
    private Set<Integer> setOfShares;

    /**
     * threshold of the node on that this instance is performed
     */
    private int threshold;

    private int numberOfFulfilledChildren = 0;

    private ArrayList<Pair<Integer, ArrayList<Integer>>> list; //hooray for good variable names...

    private boolean fulfilled = false;

    private boolean leaf = false;

    private int leafNumber;

    public MinimalFulfillingSubsetVisitor(Set<Integer> setOfShareIdentifers) {
        this.setOfShares = setOfShareIdentifers;
        list = new ArrayList<Pair<Integer, ArrayList<Integer>>>();
    }

    @Override
    public Pair<Integer, ArrayList<Integer>> getResultOfCurrentNode() {
        if (fulfilled) {
            ArrayList<Integer> arraylist = new ArrayList<>();
            Integer minimalNumberOfFulfilledLeafs = 0;
            if (leaf) {
                arraylist.add(leafNumber);
                minimalNumberOfFulfilledLeafs = 1;
            } else {
                Integer counter = 0;

                Collections.sort(list);

                for (Pair<Integer, ArrayList<Integer>> entry : list) {
                    counter++;
                    minimalNumberOfFulfilledLeafs = minimalNumberOfFulfilledLeafs
                            + entry.getFirst();
                    arraylist.addAll(entry.getSecond());

                    if (counter.equals(threshold))
                        break;
                }
            }
            return new Pair<Integer, ArrayList<Integer>>(
                    minimalNumberOfFulfilledLeafs, arraylist);
        } else {
            return new Pair<Integer, ArrayList<Integer>>(0, null);
        }
    }

    @Override
    public MinimalFulfillingSubsetVisitor getVisitorForNextChild() {
        return new MinimalFulfillingSubsetVisitor(setOfShares);
    }

    @Override
    public void putResultOfChild(Pair<Integer, ArrayList<Integer>> input) {
        if (!(input.getFirst() == 0)) {
            numberOfFulfilledChildren = numberOfFulfilledChildren + 1;
            if (numberOfFulfilledChildren == threshold)
                fulfilled = true;
            list.add(input);
        }
    }

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
                        "Tree contains a node with children and Threshold 0 \n 0 is not a valid threshold");
            }
        }
    }

}
