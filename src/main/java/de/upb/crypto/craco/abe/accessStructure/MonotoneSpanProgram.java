package de.upb.crypto.craco.abe.accessStructure;

import de.upb.crypto.craco.abe.accessStructure.exception.NoSatisfyingSet;
import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.craco.abe.accessStructure.util.MinimalFulfillingSubsetVisitor;
import de.upb.crypto.craco.abe.accessStructure.util.MonotoneSpanProgramGetMatrixVisitor;
import de.upb.crypto.craco.abe.accessStructure.util.Pair;
import de.upb.crypto.craco.abe.accessStructure.util.TreeNode;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.*;

/**
 * Access structure realized by using the monotone span programs.
 *
 * @param <E> type of the attributes
 * @author pschleiter, Fabian Eidens (refactor)
 */
public class MonotoneSpanProgram extends AccessStructure {

    public MonotoneSpanProgram(Policy policy, Zp field) {
        super(policy, field);
    }

    @Override
    public Map<Integer, ZpElement> getShares(ZpElement secret) throws WrongAccessStructureException {
        ArrayList<ArrayList<ZpElement>> matrix = new ArrayList<>();
        int size = generateMatrix(matrix);
        ArrayList<ZpElement> randomVector = new ArrayList<>();
        randomVector.add(secret);

        for (int counter = 1; counter < size; counter++) {
            randomVector.add(field.getUniformlyRandomElement());
        }

        HashMap<Integer, ZpElement> result = new HashMap<>();
        int counter = 0;

        for (ArrayList<ZpElement> row : matrix) {
            Iterator<ZpElement> iteratorVector = randomVector.iterator();
            ZpElement value = field.getZeroElement();
            for (ZpElement entry : row) {
                value = value.add(entry.mul(iteratorVector.next()));
            }
            result.put(counter, value);
            counter++;
        }

        return result;
    }

    public int getNumberOfColumns() throws WrongAccessStructureException {
        ArrayList<ArrayList<ZpElement>> convert = new ArrayList<>();
        return generateMatrix(convert);
    }

    @Override
    public Map<Integer, ZpElement> getSolvingVector(
            Set<? extends PolicyFact> setOfParties) throws NoSatisfyingSet, WrongAccessStructureException {

        // at first identify the minimal number of rows that are necessary to
        // reconstruct the secret
        MinimalFulfillingSubsetVisitor minimalSubsetVisitor =
                new MinimalFulfillingSubsetVisitor(getSharesOfReceivers(setOfParties));
        TreeNode tree = thresholdTree;
        Pair<Integer, ArrayList<Integer>> fulfillingSet = tree.performVisitor(minimalSubsetVisitor);

        if (fulfillingSet.getFirst() == 0)
            throw new NoSatisfyingSet("Given set does not satisfy the access structure");

        int numberOfRows = fulfillingSet.getFirst();

        ArrayList<ArrayList<ZpElement>> convert = new ArrayList<>();
        ZpElement[][] matrix = convertRepresentationOfMatrix(generateMatrix(convert), convert);

        // calculate the submatrix
        ZpElement[][] submatrix = new ZpElement[numberOfRows][];
        Integer[] labeling = new Integer[numberOfRows];

        int counter = 0;
        for (Integer id : fulfillingSet.getSecond()) {
            labeling[counter] = id;
            submatrix[counter++] = matrix[id.intValue()];
        }

        ZpElement[] vector = calculateSolvingVector(submatrix);

        HashMap<Integer, ZpElement> result = new HashMap<>();
        int i = 0;
        for (ZpElement ele : vector) {
            result.put(labeling[i], ele);
            i++;
        }

        return result;
    }

    /**
     * This method returns a String, that contain a representation of the
     * monotone span program contained by this class. The layout of the string
     * is designed for access structures that contain only threshold nodes with at
     * most 999 leaves.
     *
     * @return String representing the monotone span program
     * @throws WrongAccessStructureException
     */
    public String toStringFor3DigitsGates() throws WrongAccessStructureException {
        ArrayList<ArrayList<ZpElement>> matrix = new ArrayList<>();
        int size = generateMatrix(matrix);
        String output = new String();

        int rowCounter = 0;
        int columnCounter = 0;

        for (ArrayList<ZpElement> row : matrix) {
            columnCounter = 0;
            output = output.concat("( ");
            for (ZpElement entry : row) {
                columnCounter++;
                output = output.concat(String.format("%3d ", entry.getInteger().shortValue()));
            }

            for (; columnCounter <= size; columnCounter++) {
                output = output.concat(String.format("%3d ", 0));
            }
            output = output.concat(String.format(") %s\n", shareReceivers.get(rowCounter++).toString()));
        }

        return output;
    }

    /**
     * This method gets a <code>matrix</code> and returns a vector v such that v
     * * matrix = (1,0,...,0)
     *
     * @param matrix
     * @return
     * @throws NoSatisfyingSet will be thrown if no such vector v exists
     */
    private ZpElement[] calculateSolvingVector(ZpElement[][] matrix) throws NoSatisfyingSet {
        int numberOfRows = matrix.length;
        int numberOfColumns = matrix[0].length;
        int counterRows = 0;
        int counterColumns = numberOfColumns - 1;

        // vectors contains the combination of the different rows of the input
        // matrix, that leads to the corresponding row in matrix
        ZpElement[][] vectors = new ZpElement[numberOfRows][];

        for (int i = 0; i < numberOfRows; i++) {
            ZpElement[] vector = new ZpElement[numberOfRows];
            for (int j = 0; j < numberOfRows; j++) {
                if (j == i)
                    vector[j] = field.getOneElement();
                else
                    vector[j] = field.getZeroElement();
            }
            vectors[i] = vector;
        }

        // Gauss is applied
        while ((counterRows != numberOfRows) && (counterColumns != -1)) {

            if (matrix[counterRows][counterColumns].equals(field.getZeroElement())) {
                int i = counterRows + 1;
                while (i < numberOfRows) {
                    if (!matrix[i][counterColumns].equals(field.getZeroElement())) {
                        break;
                    }
                    i++;
                }
                if (i == numberOfRows) {
                    counterColumns--;
                    continue;
                }
                swapRows(vectors, matrix, i, counterRows);
            }

            for (int j = (counterRows + 1); j < numberOfRows; j++) {
                subtractRowIFromRowJ(vectors, matrix, counterColumns, counterRows, j);
            }

            counterColumns--;
            counterRows++;
        }

        counterRows--;

        if ((counterColumns != -1) || (matrix[counterRows][0].equals(field.getZeroElement())))
            throw new NoSatisfyingSet("Given set does not satisfy the access structure");

        for (int k = 0; k < vectors[0].length; k++) {
            vectors[counterRows][k] = (ZpElement) vectors[counterRows][k].div(matrix[counterRows][0]);
        }

        return vectors[counterRows];

    }

    /**
     * change the representation of the matrix from a 2 dimensional ArrayList to
     * a 2 dimensional array
     *
     * @param size
     * @param matrix
     * @return
     */
    private ZpElement[][] convertRepresentationOfMatrix(int size, ArrayList<ArrayList<ZpElement>> matrix) {
        int i = 0;
        int j = 0;
        ZpElement[][] result = new ZpElement[matrix.size()][size];
        ZpElement zero = field.getZeroElement();

        for (ArrayList<ZpElement> row : matrix) {
            j = 0;
            for (ZpElement entry : row) {
                result[i][j] = entry;
                j++;
            }
            for (; j < size; j++) {
                zero = field.getZeroElement();
                result[i][j] = zero;
            }
            i++;
        }
        return result;
    }

    /**
     * Generates the matrix for access structure represented by this instance.
     * The matrix is stored in the input parameter <code>matrix</code> and the
     * pairs of the labeling function is <code>attributes</code>.
     *
     * @param matrix object that contains after performing this method the matrix
     * @return the number of columns
     * @throws WrongAccessStructureException
     */
    private Integer generateMatrix(ArrayList<ArrayList<ZpElement>> matrix) throws WrongAccessStructureException {
        ArrayList<ZpElement> prefix = new ArrayList<>();
        prefix.add(field.getOneElement());
        MonotoneSpanProgramGetMatrixVisitor visitor = new MonotoneSpanProgramGetMatrixVisitor(field, prefix,
                matrix);
        thresholdTree.performVisitor(visitor);
        // add one because of input prefix
        return visitor.getResultOfCurrentNode() + 1;
    }

    /**
     * subtract the row i form the row j such that the value in row j of matrix
     * <code>matrix</code> has in column <code>column</code> the value 0. The
     * matrix i will also subtracted form row j in matrix <code>vectors</code>.
     *
     * @param vectors
     * @param matrix
     * @param column
     * @param i
     * @param j
     */
    private void subtractRowIFromRowJ(ZpElement[][] vectors, ZpElement[][] matrix, int column, int i, int j) {
        ZpElement factor = (ZpElement) field.getOneElement().div(matrix[i][column]).mul(matrix[j][column]);

        for (int k = 0; k < vectors[0].length; k++) {
            vectors[j][k] = (ZpElement) vectors[j][k].sub(factor.mul(vectors[i][k]));
        }

        for (int k = 0; k < matrix[0].length; k++) {
            matrix[j][k] = (ZpElement) matrix[j][k].sub(factor.mul(matrix[i][k]));
        }

    }

    /**
     * change the row i and j with each other in matrix <code>matrix</code> and
     * <code>vectors</code>
     *
     * @param vectors
     * @param matrix
     * @param i
     * @param j
     */
    private void swapRows(ZpElement[][] vectors, ZpElement[][] matrix, int i, int j) {
        ZpElement[] tempVector = vectors[i];
        ZpElement[] tempRow = matrix[i];

        vectors[i] = vectors[j];
        matrix[i] = matrix[j];

        vectors[j] = tempVector;
        matrix[j] = tempRow;
    }

    public HashMap<Integer, PolicyFact> getAttributes() {
        return shareReceivers;
    }

    @Override
    public Map<Integer, ZpElement> completeShares(ZpElement secret,
                                                  Map<Integer, ZpElement> partialShares) throws IllegalArgumentException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean checkShareConsistency(ZpElement secret, Map<Integer, ZpElement> shares) {
        throw new UnsupportedOperationException();
    }
}
