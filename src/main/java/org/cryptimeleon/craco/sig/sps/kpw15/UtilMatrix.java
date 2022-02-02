package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Function;

/**
 * A very limited implementation of matrix math tailored to the operations required by the KPW15 SPS scheme
 * */
public class UtilMatrix<X> {

    /**
     * a linear representation of the matrix
     * */
    protected X[] contents;

    /**
     * The number of rows this matrix has
     * */
    protected int rows;

    /**
     * The number of columns this matrix has
     * */
    protected int columns;


    public UtilMatrix(int rows, int columns, Vector<X> contents) {
        this(rows, columns, (X[]) contents.stream().toArray());
    }

    public UtilMatrix(int rows, int columns, X... contents) {
        this.contents = contents;
        this.rows = rows;
        this.columns = columns;
    }


    /**
     * access an element within this matrix. Note that matrix elements are 1-indexed!
     * */
    public X get(int row, int column) {
        return contents[(rows * (column - 1)) + (row - 1)];
    }

    public void set(int row, int column, X value) {
        this.contents[(rows * (column - 1)) + (row - 1)] = value;
    }

    public Vector<X> getLinearRepresentation() { return new Vector<X>(contents); }


    /**
     * Return a transposed version of this matrix
     * */
    public UtilMatrix<X> getTransposed()
    {
        UtilMatrix<X> transposed = new UtilMatrix<X>(this.columns, this.rows);

        for (int r = 1; r <= rows; r++) {
            for (int c = 1; c <= columns; c++) {
                transposed.set(c,r, this.get(r,c));
            }
        }
        return transposed;
    }

}
