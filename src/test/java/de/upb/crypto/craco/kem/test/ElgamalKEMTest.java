package de.upb.crypto.craco.kem.test;

import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.SymmetricKey;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPrivateKey;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism.KeyAndCiphertext;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEM;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEMCiphertext;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.structures.RingGroup;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class ElgamalKEMTest {

    static ElgamalPrivateKey sk;
    static ElgamalKEM kem;
    static HashFunction md;

    /*
     * parameters from http://www.ietf.org/rfc/rfc5114
     */
    static String p =
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
    static String q = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
    static String g =
            "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

    @BeforeClass
    public static void setup() throws NoSuchAlgorithmException {

        /*generate field to define group*/
        Zp zp = new Zp(new BigInteger(p, 16));

        /*multiplicative subgroup of field*/
        RingGroup zpStar = RingGroup.unitGroupOf(zp);

        md = new SHA256HashFunction();

        kem = new ElgamalKEM(zpStar, md);


        KeyPair keypair = kem.generateKeyPair();

        sk = (ElgamalPrivateKey) keypair.getSk();


    }

    @Test
    public void testEncryption() {
        System.out.println("Generate encapsulation.");
        KeyAndCiphertext<? extends SymmetricKey> kAndC = kem.encaps(sk.getPublicKey());

        SymmetricKey k = kAndC.key;
        ElgamalKEMCiphertext C = (ElgamalKEMCiphertext) kAndC.encapsulatedKey;

        /*check that key has correct size*/
        assertEquals(md.getOutputLength(), ((ByteArrayImplementation) k).length());

        System.out.println("Generate new encapsultion and check that different");
        /*check that each invocation yields new key*/
        assertFalse(kem.encaps(sk.getPublicKey()).key.equals(k));


        System.out.println("Check that descapsulation provides same key.");
        /*check decapsultation*/
        assertEquals(k, kem.decaps(C, sk));

        /* modify symmetric part by one bit*/
        ElgamalKEMCiphertext Cprime = new ElgamalKEMCiphertext(C.getElgamalCipherText(),
                C.getSymmetricEncryption().xor(
                        new ByteArrayImplementation(new byte[]{1})
                )
        );
        System.out.println("Check non-malleability");
        ByteArrayImplementation kprime = kem.decaps(Cprime, sk);
        assertTrue(kprime.equals(new ByteArrayImplementation(new byte[0])));
    }
}

