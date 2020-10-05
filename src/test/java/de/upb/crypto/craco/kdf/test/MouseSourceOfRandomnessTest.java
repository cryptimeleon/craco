package de.upb.crypto.craco.kdf.test;

import de.upb.crypto.craco.kdf.interfaces.source.MouseSourceOfRandomness;
import org.junit.Test;

public class MouseSourceOfRandomnessTest {


    @Test
    public void testGeneration() {
        MouseSourceOfRandomness source = new MouseSourceOfRandomness(256);
//		KeyMaterial km = source.sampleElement();
//		assertTrue(source.getOutputLength() == km.getUniqueByteRepresenation().length *8);
//		assertTrue (km.getMinEntropyInBit() == 256);
    }
}
