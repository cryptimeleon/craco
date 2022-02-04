package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

/**
 * Performs the simple matrix operations required by the KPW15 SPS scheme.
 * */
public class MatrixUtility {

    /**
     * Interpret two arrays as matrices and multiply them
     * */
    public static ZpElement[] matrixMul(ZpElement[] A, int rowsA, int columnsA,
                                           ZpElement[] B, int rowsB, int columnsB) {
        //check if matrices can be multiplied
        if(A.length != rowsA * columnsA || B.length != rowsB * columnsB) {
            throw new IllegalArgumentException("The given vectors length does not match its matrix dimensions" );
        }

        if(columnsA != rowsB) {
            throw new IllegalArgumentException(
                    String.format("function is only defined for matrices where columns_A == rows_B : got %d x %d",
                            columnsA,
                            rowsB)
            );
        }

        ZpElement[] multiplied = new ZpElement[rowsA * columnsB];

        // now, calculate the individual elements

        for (int r = 1; r <= rowsA; r++) {
            for (int c = 1; c <= columnsB; c++) {

                ZpElement value = B[0].getStructure().getZeroElement(); //TODO check if this is correct

                for (int i = 1; i <= columnsA; i++) {
                    value = value.add(
                            A[getMatrixIndex(rowsA, columnsA, r, i)].mul(B[getMatrixIndex(rowsB, columnsB, i, c)]));
                }

                multiplied[getMatrixIndex(rowsA, columnsB, r,c)] = value;
            }
        }

        return multiplied;
    }

    /**
     * Kiltz et al. define e(A,B) for two matrices as AxB.
     * We apply the bilinear map to each row/column in order to calculate the result
     * */
    public static GroupElementVector matrixMul( BilinearMap bMap,
                                                GroupElementVector A, int rowsA, int columnsA,
                                                GroupElementVector B, int rowsB, int columnsB) {
        //check if matrices can be multiplied
        if(A.length() != rowsA * columnsA || B.length() != rowsB * columnsB) {
            throw new IllegalArgumentException("The given vectors length does not match its matrix dimensions");
        }

        if(columnsA != rowsB) {
            throw new IllegalArgumentException(
                    String.format("function is only defined for matrices where columns_A == rows_B : got %d x %d",
                            columnsA,
                            rowsB)
            );
        }

        //TODO check for 1 dim

        GroupElement[] multiplied = new GroupElement[rowsA * columnsB];

        // now, calculate the individual elements

        for (int r = 1; r <= rowsA; r++) {
            for (int c = 1; c <= columnsB; c++) {

                GroupElement value = bMap.getGT().getNeutralElement();

                for (int i = 1; i <= columnsA; i++) {
                    value = value.op(
                            bMap.apply(A.get(getMatrixIndex(rowsA, columnsA, r, i)),
                                    B.get(getMatrixIndex(rowsB, columnsB, i, c))
                            )
                    );
                }

                value.compute();
                multiplied[getMatrixIndex(rowsA, columnsB, r,c)] = value;
            }
        }

        //TODO test optimization

        return new GroupElementVector(multiplied);
    }

    /**
     * Calculate a linear index for the given matrix position
     * */
    public static int getMatrixIndex(int rows, int columns, int row, int column)
    {
        return (rows * (column - 1)) + (row - 1);
    }


    public static GroupElement[] calculateSigma1Matrix(GroupElement[] message, ZpElement[] K) {

        // multiplying message(1 x n+1 matrix) and K(n+1 x 2 matrix) results in a 1 x 2 matrix

        int rows = 1; //TODO optimize
        int columns = 2;

        GroupElement[] multiplied = new GroupElement[rows * columns];

        for (int c = 1; c <= columns; c++) {

            GroupElement value = message[0].getStructure().getNeutralElement();

            for (int i = 1; i <= message.length; i++) {

                ZpElement exponentK = K[getMatrixIndex(message.length, 2, i, c)];
                GroupElement messageElement = message[i - 1];

                value = value.op(messageElement.pow(exponentK));
            }

            value.compute();
            multiplied[c-1] = value;
        }

        return multiplied;
    }

}
