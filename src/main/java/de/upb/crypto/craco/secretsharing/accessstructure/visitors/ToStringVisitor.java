package de.upb.crypto.craco.secretsharing.accessstructure.visitors;

import de.upb.crypto.craco.secretsharing.accessstructure.exceptions.WrongAccessStructureException;
import de.upb.crypto.craco.secretsharing.accessstructure.utils.TreeNode;

/**
 * Visitor class that formats the given {@link AccessStructure} as a printable string.
 */
public class ToStringVisitor implements Visitor<String> {

    String output = "";

    TreeNode currentNode;

    boolean firstAttr = true;

    public ToStringVisitor() {
    }

    @Override
    public String getResultOfCurrentNode() throws WrongAccessStructureException {
        if (currentNode.getNumberOfChildren() == 0) {
            TreeNode leaf = currentNode;
            return leaf.toString();
        } else {
            return output.concat(String.format("' %d )",
                    currentNode.getThreshold()));
        }
    }

    @Override
    public Visitor<String> getVisitorForNextChild()
            throws WrongAccessStructureException {
        return new ToStringVisitor();
    }

    @Override
    public void putResultOfChild(String input) {
        if (firstAttr) {
            output = output.concat(String.format("%s", input));
            firstAttr = false;
        } else
            output = output.concat(String.format(", %s", input));
    }

    @Override
    public void visit(TreeNode currentNode)
            throws WrongAccessStructureException {
        this.currentNode = currentNode;
        output = new String("( ");
    }

}
