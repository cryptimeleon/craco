package de.upb.crypto.craco.enc.streaming.test;

import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingCBCAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import de.upb.crypto.craco.interfaces.KeyPair;
import de.upb.crypto.craco.interfaces.SymmetricKey;

public class StreamingAESParams {

    public static StreamingEncryptionSchemeParams[] getParams() {
        StreamingGCMAES GCMAES = new StreamingGCMAES();
        SymmetricKey GCMkey = GCMAES.generateSymmetricKey();
        KeyPair GCMkp = new KeyPair(GCMkey, GCMkey);
        StreamingCBCAES CBCAES = new StreamingCBCAES();
        SymmetricKey CBCkey = CBCAES.generateSymmetricKey();
        KeyPair CBCkp = new KeyPair(CBCkey, CBCkey);

        StreamingGCMAESPacketMode GCMAESPacket = new StreamingGCMAESPacketMode();

        StreamingEncryptionSchemeParams[] toReturn = {new StreamingEncryptionSchemeParams(CBCAES, CBCkp),
                new StreamingEncryptionSchemeParams(GCMAES, GCMkp),
                new StreamingEncryptionSchemeParams(GCMAESPacket, GCMkp)};
        return toReturn;
    }
}
