package de.upb.crypto.craco.enc.streaming.params;

import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.enc.SymmetricKey;
import de.upb.crypto.craco.enc.streaming.StreamingEncryptionSchemeParams;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingCBCAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;

public class StreamingAESParams {

    public static StreamingEncryptionSchemeParams[] getParams() {
        StreamingGCMAES GCMAES = new StreamingGCMAES();
        SymmetricKey GCMkey = GCMAES.generateSymmetricKey();
        KeyPair GCMkp = new KeyPair(GCMkey, GCMkey);
        StreamingCBCAES CBCAES = new StreamingCBCAES();
        SymmetricKey CBCkey = CBCAES.generateSymmetricKey();
        KeyPair CBCkp = new KeyPair(CBCkey, CBCkey);

        StreamingGCMAESPacketMode GCMAESPacket = new StreamingGCMAESPacketMode();

        /*StreamingEncryptionSchemeParams[] toReturn = {new StreamingEncryptionSchemeParams(CBCAES, CBCkp),
                new StreamingEncryptionSchemeParams(GCMAES, GCMkp),
                new StreamingEncryptionSchemeParams(GCMAESPacket, GCMkp)};*/
        StreamingEncryptionSchemeParams[] toReturn = {
                new StreamingEncryptionSchemeParams(CBCAES, CBCkp),
        };
        return toReturn;
    }
}
