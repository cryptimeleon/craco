package de.upb.crypto.craco.test;

import de.upb.crypto.math.hash.UniqueByteRepresentable;

public class UniqueByteRepresentableParams {

    private UniqueByteRepresentable instanceOne;

    private UniqueByteRepresentable instanceTwo;

    public UniqueByteRepresentable getInstanceOne() {
        return instanceOne;
    }

    public UniqueByteRepresentable getInstanceTwo() {
        return instanceTwo;
    }

    /**
     * Sets up test params where <code>instanceTwo</code> is a copy of <code>instanceTwo</code> such that they yield
     * the same UniqueBytes.
     *
     * @param instanceOne
     * @param instanceTwo
     */
    public UniqueByteRepresentableParams(UniqueByteRepresentable instanceOne, UniqueByteRepresentable instanceTwo) {
        super();
        this.instanceOne = instanceOne;
        this.instanceTwo = instanceTwo;
    }

}
