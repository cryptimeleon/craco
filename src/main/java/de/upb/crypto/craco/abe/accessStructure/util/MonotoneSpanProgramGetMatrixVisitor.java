package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.ArrayList;

/**
 * This Visitor calculates the matrix for the tree it is performed on
 *
 * @param <E> type of the attributes
 * @author pschleiter, Fabian Eidens (refactor)
 */
public class MonotoneSpanProgramGetMatrixVisitor implements Visitor<Integer> {

    /**
     * Field over that the matrix is calculated
     */
    private Zp field;

    /**
     * Contain the values for the columns belong to higher hierarchies
     */
    private ArrayList<ZpElement> prefix;

    /**
     * matrix containing all rows calculated so far
     */
    private ArrayList<ArrayList<ZpElement>> matrix;

    /**
     * the threshold of the node the visitor is performed on
     */
    private int threshold;

    /**
     * internal counter, that count how many visitors for children were
     * requested so far
     */
    private ZpElement counterN;

    /**
     * the number of columns this subtree with the current node as root node
     * need in the monotone span program
     */
    private int ownOffset = 0;

    /**
     * the current node
     */
    private TreeNode node;

    /**
     * @param field  field over that the monotone span program is calculated
     * @param prefix the values for the columns belong to higher hierarchies
     * @param matrix matrix containing all rows calculated so far and the new rows
     *               will be stored in this instance
     */
    public MonotoneSpanProgramGetMatrixVisitor(Zp field, ArrayList<ZpElement> prefix,
                                               ArrayList<ArrayList<ZpElement>> matrix) {
        this.field = field;
        this.prefix = new ArrayList<>();
        for (ZpElement ele : prefix) {
            this.prefix.add(field.getOneElement().mul(ele));
        }
        this.matrix = matrix;
        counterN = field.getZeroElement();
    }

    @Override
    public Integer getResultOfCurrentNode() {

        if (threshold == 0) {
            return 0;
        }

        return (ownOffset + threshold - 1);
    }

    @Override
    public MonotoneSpanProgramGetMatrixVisitor getVisitorForNextChild() throws WrongAccessStructureException {
        ZpElement value = field.getOneElement();

        counterN = counterN.add(field.getOneElement());

        // calculate the new values for the counterN child
        @SuppressWarnings("unchecked")
        ArrayList<ZpElement> tempPrefix = (ArrayList<ZpElement>) prefix.clone();
        if (threshold != 0) {
            for (int counterT = 1; counterT < threshold; counterT++) {
                value = value.mul(counterN);
                tempPrefix.add(value);
            }
        } else {
            throw new WrongAccessStructureException(
                    "Tree contains a node with children and Threshold 0 \n 0 is not a valid threshold");
        }
        // extend the prefix vector for all further children
        for (int counter = 0; counter < ownOffset; counter++) {
            tempPrefix.add(field.getZeroElement());
        }

        return new MonotoneSpanProgramGetMatrixVisitor(field, tempPrefix, matrix);
    }

    @Override
    public void putResultOfChild(Integer input) {
        ownOffset += input;
    }

    @Override
    public void visit(TreeNode currentNode) {
        node = currentNode;
        threshold = node.getThreshold();
        int numberOfNodes = node.getNumberOfChildren();
        // check if the current node is a leaf, then add a new row
        if (numberOfNodes == 0) {
            matrix.add(prefix);
        }

    }

}
