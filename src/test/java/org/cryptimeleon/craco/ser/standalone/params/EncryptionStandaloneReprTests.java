package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalEncryption;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingCBCAES;
import org.cryptimeleon.craco.kem.StreamingHybridEncryptionScheme;
import org.cryptimeleon.craco.kem.asym.elgamal.ElgamalKEM;
import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.counting.CountingGroup;

public class EncryptionStandaloneReprTests extends StandaloneReprSubTest {
    Group group = new CountingGroup("testgroup", 128);
    ElgamalKEM elgamalKEM = new ElgamalKEM(group, new SHA256HashFunction());

    public void testElGamal() {
        test(elgamalKEM);
        test(new ElgamalEncryption(group));
    }

    public void testStreamingHybrid() {
        test(new StreamingHybridEncryptionScheme(new StreamingCBCAES(), elgamalKEM));
    }
}
