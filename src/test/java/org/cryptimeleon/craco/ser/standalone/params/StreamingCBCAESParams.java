package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingCBCAES;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class StreamingCBCAESParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StreamingCBCAES.class, new StreamingCBCAES());
    }
}
