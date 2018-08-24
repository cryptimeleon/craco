package de.upb.crypto.craco.test;

import de.upb.crypto.math.serialization.Representation;
import org.junit.Assert;
import org.junit.Test;

public class AnnotationTest {

    @Test
    public void testAnnotations() {
        TestData data0 = new TestData();
        Representation repr = data0.getRepresentation();
        System.out.println(repr);
        TestData data1 = new TestData(repr);
        System.out.println(data1.getRepresentation());
        Assert.assertTrue(data0.equals(data1));
    }
}
