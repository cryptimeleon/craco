package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.SymmetricKey;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;
import de.upb.crypto.craco.enc.streaming.test.StreamingEncryptionSchemeParams;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingCBCAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;

import java.security.Key;
import java.security.SecureRandom;

public class StreamingAESParams implements TestParameterProvider {
    @Override
    public Object get() {
        StreamingGCMAES GCMAES = new StreamingGCMAES();
        SymmetricKey GCMkey = GCMAES.generateSymmetricKey();
        KeyPair GCMkp = new KeyPair(GCMkey, GCMkey);
        SymmetricKey wrongGCMKey = GCMAES.generateSymmetricKey();
        KeyPair wrongGCMkp = new KeyPair(GCMkey, wrongGCMKey);

        StreamingCBCAES CBCAES = new StreamingCBCAES();
        SymmetricKey CBCkey = CBCAES.generateSymmetricKey();
        KeyPair CBCkp = new KeyPair(CBCkey, CBCkey);
        SymmetricKey wrongCBCkey = CBCAES.generateSymmetricKey();
        KeyPair wrongCBCkp = new KeyPair(CBCkey, wrongCBCkey);

        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[1024];
        random.nextBytes(randomBytes);
        PlainText plainText = new ByteArrayImplementation(randomBytes);

        StreamingGCMAESPacketMode GCMAESPacket = new StreamingGCMAESPacketMode();

        return new EncryptionSchemeTestParam[]{
                new EncryptionSchemeTestParam(CBCAES, plainText, CBCkp, wrongCBCkp),
                new EncryptionSchemeTestParam(GCMAES, plainText, GCMkp, wrongGCMkp),
                new EncryptionSchemeTestParam(GCMAESPacket, plainText, GCMkp, wrongGCMkp)
        };
    }
}
