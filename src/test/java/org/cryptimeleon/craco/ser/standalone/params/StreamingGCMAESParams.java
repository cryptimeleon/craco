package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingGCMAES;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class StreamingGCMAESParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StreamingGCMAES.class, new StreamingGCMAES());
    }
}
