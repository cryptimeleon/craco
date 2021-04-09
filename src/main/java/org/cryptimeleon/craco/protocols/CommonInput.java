package org.cryptimeleon.craco.protocols;


import org.cryptimeleon.math.structures.cartesian.Vector;

import java.util.List;

public interface CommonInput {
    CommonInput EMPTY = new EmptyCommonInput();
    public class EmptyCommonInput implements CommonInput {

    }

    public class CommonInputVector extends Vector<CommonInput> implements CommonInput {
        public CommonInputVector(CommonInput... commonInputs) {
            super(commonInputs);
        }

        public CommonInputVector(List<? extends CommonInput> commonInputs) {
            super(commonInputs);
        }
    }
}
