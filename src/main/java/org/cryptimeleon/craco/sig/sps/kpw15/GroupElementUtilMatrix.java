package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Arrays;

/**
 * A very limited implementation of matrix math tailored to the operations required by the KPW15 SPS scheme.
 * Unlike (@link UtilMatrix), this class operates on GroupElements and supports math operations
 * */
public class GroupElementUtilMatrix extends UtilMatrix<GroupElement>{


    public GroupElementUtilMatrix(int rows, int columns, Vector<GroupElement> contents) {
        super(rows, columns, contents);
    }

    public GroupElementUtilMatrix(int rows, int columns, GroupElement... contents) {
        super(rows, columns, contents);
    }


    /**
     * Multiply this matrix by another B.
     * A x B
     * */
    public GroupElementUtilMatrix mul(GroupElementUtilMatrix B) {

        //check if matrices can be multiplied
        if(this.columns != B.rows) {
            throw new IllegalArgumentException("matrix multiplication is only defined for matrices where" +
                    "columns_A == rows_B");
        }

        GroupElementUtilMatrix multiplied = new GroupElementUtilMatrix(this.rows, B.columns);

        // now, calculate the individual elements

        for (int r = 1; r <= multiplied.rows; r++) {
            for (int c = 1; c <= multiplied.columns; c++) {

                GroupElement value = B.get(1,1).getStructure().getNeutralElement();

                for (int i = 1; i <= this.columns; i++) {
                    value = value.op(this.get(r, i).op(B.get(i, c))); //TODO what is going on here?
                }

                value.compute();

                multiplied.set(r,c, value);
            }
        }

        return multiplied;
    }

    /**
     * Multiply this matrix by a vector b.
     * A x b
     * */
    public GroupElementUtilMatrix mul(Vector<GroupElement> B) {
        return this.mul(new GroupElementUtilMatrix(1, B.length(), B));
    }

    /**
     * Multiply this matrix by a single element b.
     * */
    public GroupElementUtilMatrix mul(GroupElement b) {

        GroupElementUtilMatrix Axb = new GroupElementUtilMatrix(this.rows,
                this.columns,
                new GroupElementVector(
                (GroupElement[]) Arrays.stream(contents).map( x -> x.op(b).compute()).toArray() //TODO check if this is the correct op
                )
        );

        return Axb;
    }

    /**
     * Add this matrix to another
     * A + B
     * */
    public GroupElementUtilMatrix add(GroupElementUtilMatrix B) {

        if(!(this.rows == B.rows && this.columns == B.columns )) {
            throw new IllegalArgumentException("Operation undefined for matrices of different sizes");
        }

        GroupElementUtilMatrix AplusB = new GroupElementUtilMatrix(this.rows, this.columns);

        for (int i = 0; i < contents.length; i++) {
            AplusB.contents[i] = this.contents[i].op(B.contents[i]);
        }

        return AplusB;
    }

}
