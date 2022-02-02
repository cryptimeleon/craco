package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;

/**
 * A very limited implementation of matrix math tailored to the operations required by the KPW15 SPS scheme.
 * This class operates on ZpElements and supports math operations
 * */
public class ZpElementUtilMatrix extends UtilMatrix<ZpElement>{

    public ZpElementUtilMatrix(int rows, int columns, Vector<ZpElement> contents) {
        super(rows, columns, contents);
    }

    public ZpElementUtilMatrix(int rows, int columns, ZpElement... contents) {
        super(rows, columns, contents);
    }

    /**
     * Converts a Matrix of exponents to a group element matrix by calculating
     * g^{a^{m,n}} for all elements a^{m,n} in the matrix
     * */
    public GroupElementUtilMatrix calculateGroupElementMatrix(GroupElement g)
    {
        try{
            GroupElementVector linearGs = new GroupElementVector(
                    (GroupElement[]) Arrays.stream(contents).map(x -> g.pow(x).compute()).toArray());
            return new GroupElementUtilMatrix(this.rows, this.columns, linearGs);
        }
        catch (Exception e){
            throw new IllegalArgumentException("This operation is undefined for non-ZpElement matrices");
        }
    }

    public ZpElementUtilMatrix mul(ZpElementUtilMatrix B) {
        //check if matrices can be multiplied
        if(this.columns != B.rows) {
            throw new IllegalArgumentException("matrix multiplication is only defined for matrices where" +
                    "columns_A == rows_B");
        }

        ZpElementUtilMatrix multiplied = new ZpElementUtilMatrix(this.rows, B.columns);

        // now, calculate the individual elements

        for (int r = 1; r <= multiplied.rows; r++) {
            for (int c = 1; c <= multiplied.columns; c++) {

                ZpElement value = B.get(1,1).getStructure().getOneElement();

                for (int i = 1; i <= this.columns; i++) {
                    value = value.add(this.get(r, i).mul(B.get(i, c))); //TODO what is going on here?
                }

                multiplied.set(r,c, value);
            }
        }

        return multiplied;
    }



}
