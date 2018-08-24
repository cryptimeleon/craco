package de.upb.crypto.craco.test;


import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.ArrayList;
import java.util.Collection;

@RunWith(value = Parameterized.class)
public class UniqueByteRepresentableTest {

    private UniqueByteRepresentableParams params;

    public UniqueByteRepresentableTest(UniqueByteRepresentableParams params) {
        this.params = params;
    }

    @Test
    void checkForCorrectness() {
        HashFunction hash = new SHA256HashFunction();
        Assert.assertArrayEquals(hash.hash(params.getInstanceOne()), hash.hash(params.getInstanceTwo()));
    }


    @Parameters(name = "{index}: {0}")
    public static Collection<UniqueByteRepresentableParams> getParams() {
        ArrayList<UniqueByteRepresentableParams> list = new ArrayList<UniqueByteRepresentableParams>();

        return list;
    }
}
