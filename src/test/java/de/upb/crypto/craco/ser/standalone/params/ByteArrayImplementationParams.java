package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class ByteArrayImplementationParams {

    public static StandaloneTestParams get() {
        ByteArrayImplementation bai = new ByteArrayImplementation("THISISATESTSTRING".getBytes());
        return new StandaloneTestParams(bai.getClass(), bai);
    }
}
