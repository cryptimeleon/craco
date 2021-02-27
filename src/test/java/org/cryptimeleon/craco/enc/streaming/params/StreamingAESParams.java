package org.cryptimeleon.craco.enc.streaming.params;

import org.cryptimeleon.craco.enc.EncryptionKeyPair;
import org.cryptimeleon.craco.enc.SymmetricKey;
import org.cryptimeleon.craco.enc.streaming.StreamingEncryptionSchemeParams;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingCBCAES;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingGCMAES;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;

public class StreamingAESParams {

    public static StreamingEncryptionSchemeParams[] getParams() {
        StreamingGCMAES GCMAES = new StreamingGCMAES();
        SymmetricKey GCMkey = GCMAES.generateSymmetricKey();
        EncryptionKeyPair GCMkp = new EncryptionKeyPair(GCMkey, GCMkey);
        StreamingCBCAES CBCAES = new StreamingCBCAES();
        SymmetricKey CBCkey = CBCAES.generateSymmetricKey();
        EncryptionKeyPair CBCkp = new EncryptionKeyPair(CBCkey, CBCkey);

        StreamingGCMAESPacketMode GCMAESPacket = new StreamingGCMAESPacketMode();

        StreamingEncryptionSchemeParams[] toReturn = {new StreamingEncryptionSchemeParams(CBCAES, CBCkp),
                new StreamingEncryptionSchemeParams(GCMAES, GCMkp),
                new StreamingEncryptionSchemeParams(GCMAESPacket, GCMkp)};
        return toReturn;
    }
}
