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
 * @author pschleiter, Fabian Eidens (refactor)
 */
public class MonotoneSpanProgram extends AccessStructure {

    public MonotoneSpanProgram(Policy policy, Zp field) {
        super(policy, field);
    }

    /**
     * Calculates shares for the given secret.
     *
     * @param secret the secret to calculate shares for
     * @return a map mapping each share index to the corresponding share field element
     * @throws WrongAccessStructureException if monotone span program matrix generation fails
     */
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

    /**
     * Calculates number of columns of the monotone span program matrix given by this instance.
     *
     * @return number of columns of the monotone span program matrix
     * @throws WrongAccessStructureException if monotone span program matrix generation fails
     */
    public int getNumberOfColumns() throws WrongAccessStructureException {
        ArrayList<ArrayList<ZpElement>> convert = new ArrayList<>();
        return generateMatrix(convert);
    }

    /**
     * Calculates set of solving secret shares for this monotone span program.
     *
     * @param setOfParties the set of share-holding parties to consider
     * @return a fulfilling map mapping each share index to the share field element
     * @throws NoSatisfyingSet if the given set of parties cannot satisfy the monotone span program
     * @throws WrongAccessStructureException if the access structure is invalid
     */
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
     * This method returns a String that contains a representation of the
     * monotone span program given by this instance. The layout of the string
     * is designed for access structures that contain only threshold nodes with at
     * most 999 leaves.
     *
     * @return string representing the monotone span program
     * @throws WrongAccessStructureException if monotone span program matrix generation fails
     */
    public String toStringFor3DigitsGates() throws WrongAccessStructureException {
        ArrayList<ArrayList<ZpElement>> matrix = new ArrayList<>();
        int size = generateMatrix(matrix);
        String output = "";

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
     * * matrix = (1,0,...,0).
     *
     * @param matrix the matrix to calculate solving vector for
     * @return the solving vector
     * @throws NoSatisfyingSet if no such vector v exists
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
     * Change the representation of the matrix from a 2 dimensional {@code ArrayList} to
     * a 2-dimensional array. Allows expanding the number of columns of the converted matrix.
     * Added columns are filled with zeros.
     *
     * @param size number of columns of the resulting array
     * @param matrix matrix to convert
     * @return two dimensional array containing the elements of the given matrix with additional columns added using the
     *         {@code size} parameter filled with zeros.
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
     * Generates the matrix for the access structure represented by this instance.
     * The matrix is stored in the input parameter <code>matrix</code> and the
     * pairs of the labeling function is <code>attributes</code>.
     *
     * @param matrix contains the generated matrix after the method is done
     * @return the number of columns
     * @throws WrongAccessStructureException if performing visitor fails
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
     * Takes the given {@code matrix} and subtracts row {@code i} from row {@code j}.
     * The subtrahend is scaled such that the resulting value in column {@code column} of row {@code j} is zero.
     * For example, for {@code i = 0, j = 1, column = 2} and a matrix {@code A} with {@code A(0,2) = 3, A(1,2) = 6},
     * the scaling factor is {@code 6/3 = 2}. Hence, the resulting matrix {@code A'} will have value
     * {@code A'(1,2) = 6 - 2 * 3 = 0}.
     * The same is done for the given {@code vectors} matrix although the scaling factor calculated from {@code matrix}
     * is reused.
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
     * Swap rows {@code i} and {@code j} in both {@code matrix} and {@code vectors}.
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
