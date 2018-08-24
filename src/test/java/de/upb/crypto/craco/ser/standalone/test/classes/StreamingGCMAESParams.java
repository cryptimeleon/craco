package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAES;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class StreamingGCMAESParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StreamingGCMAES.class, new StreamingGCMAES());
    }
}
