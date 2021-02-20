package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class StreamingGCMAESPacketModeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StreamingGCMAESPacketMode.class, new StreamingGCMAESPacketMode());
    }
}
