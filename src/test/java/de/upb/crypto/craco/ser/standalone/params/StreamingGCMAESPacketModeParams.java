package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class StreamingGCMAESPacketModeParams {
    public static StandaloneTestParams get() {
        return new StandaloneTestParams(StreamingGCMAESPacketMode.class, new StreamingGCMAESPacketMode());
    }
}
