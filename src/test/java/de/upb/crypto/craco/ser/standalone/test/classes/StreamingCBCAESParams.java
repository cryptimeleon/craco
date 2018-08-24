package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingCBCAES;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class StreamingCBCAESParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StreamingCBCAES.class, new StreamingCBCAES());
    }
}
