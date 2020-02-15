package de.upb.crypto.craco.kem.test;


import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPrivateKey;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.common.interfaces.SymmetricKey;
import de.upb.crypto.craco.common.interfaces.UnqualifiedKeyException;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.kem.abe.interfaces.proxy.DelegatedPartialDecapsulationScheme.TransformationAndDecryptionKey;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism.KeyAndCiphertext;
import de.upb.crypto.craco.kem.abe.cp.os.*;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEMCiphertext;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.bn.BarretoNaehrigProvider;
import de.upb.crypto.math.pairings.debug.DebugBilinearGroupProvider;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import de.upb.crypto.math.structures.zn.Zn.ZnElement;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Test case for Elgamal KEM with outsourcing.
 *
 * @author peter.guenther
 */
public class ElgamalLargeUniverseDelegationKEMTest {
    private static final Logger LOGGER = Logger.getLogger(ElgamalLargeUniverseDelegationKEMTest.class.getName());

    /**
     * Instantiate groups based on dummy pairing groups (Zn+) or on real pairing groups (BN curves).
     */
    static boolean debugPairing = true;

    /**
     * Size of pairing groups.
     */
    static int n = 256;

    /**
     * The scheme.
     */
    static ElgamalLargeUniverseDelegationKEM scheme;


    static LUDMasterSecret msk;
    static BilinearMap pairing;
    static HashIntoStructure hash;

    @BeforeClass
    public static void setup() throws NoSuchAlgorithmException {
        BilinearGroup bilinearGroup;
        if (debugPairing) {
            bilinearGroup = new DebugBilinearGroupProvider().provideBilinearGroup(n, BilinearGroup.Type.TYPE_3, 1);
        } else {
            BarretoNaehrigProvider fac = new BarretoNaehrigProvider();

            bilinearGroup = fac.provideBilinearGroupFromSpec(BarretoNaehrigProvider.ParamSpecs.SFC256);
        }


        LUDSetup schemeFactory;

        schemeFactory =
                new LUDSetup();

        schemeFactory.setup(bilinearGroup, new SHA256HashFunction());

        scheme = schemeFactory.getScheme();
        msk = schemeFactory.getMasterSecretKey();
        pairing = scheme.getPublicParameters().getPairingParameters().getBilinearMap();
        hash = scheme.getPublicParameters().getPairingParameters().getHashIntoZGroupExponent();

        BilinearGroup params = scheme.getPublicParameters().getPairingParameters();


        System.out.println("Pairing parameters: ");
        System.out.println(params.toString());


        System.out.println("G1:");
        System.out.println("   Generator: " + scheme.getPublicParameters().g1);

        System.out.println("G2:");
        System.out.println("   Generator: " + scheme.getPublicParameters().g2);

        System.out.println("GT:");
        System.out.println("   Generator: " + scheme.getPublicParameters().getGtGenerator());


    }


    @Test
    public void testSetup() {


    }

    @Test
    public void testSerialization() {
        checkConvertStandalone(scheme);
    }

    static Policy setupPolicy() {
        StringAttribute A = new StringAttribute("A");
        StringAttribute B = new StringAttribute("B");
        StringAttribute C = new StringAttribute("C");


        //(A or B) and (B or C)
        ThresholdPolicy policy = new ThresholdPolicy(2,
                new ThresholdPolicy(1, A, B),
                new ThresholdPolicy(1, B, C)
        );

//		ThresholdPolicy policy =  
//				new ThresholdPolicy(1, A);
        return policy;
    }

    @Test
    public void printPolicies() {
        JSONConverter converter = new JSONConverter();

        StringAttribute A = new StringAttribute("A");
        StringAttribute B = new StringAttribute("B");
        StringAttribute C = new StringAttribute("C");


        //(A or B) and (B or C)
        ThresholdPolicy policy;

        System.out.println("A | B | C");
        policy = new ThresholdPolicy(1, A, B, C);
        System.out.println(converter.serialize(policy.getRepresentation()));

        System.out.println("A & B & C");
        policy = new ThresholdPolicy(3, A, B, C);
        System.out.println(converter.serialize(policy.getRepresentation()));


        System.out.println("(A | B) & (B | C)");
        policy = new ThresholdPolicy(2,
                new ThresholdPolicy(1, A, B),
                new ThresholdPolicy(1, B, C)
        );
        System.out.println(converter.serialize(policy.getRepresentation()));

    }

    static SetOfAttributes getFulfilling() {
        //return new SetOfAttributes(new StringAttribute("A"));
        return new SetOfAttributes(new StringAttribute("B"), new StringAttribute("C"), new StringAttribute("hello"));
    }

    static SetOfAttributes getNonFulfilling() {
        return new SetOfAttributes(new StringAttribute("C"), new StringAttribute("hello"));
    }


    @Test
    public void testKeyGen() {
        //while(true) {
        BilinearMap pairing = scheme.getPublicParameters().getPairingParameters().getBilinearMap();

        Policy policy = setupPolicy();


        System.out.println("Setup encryption key for policy " + policy);

        /*
         * generate satifying and non-satisfying decryption keys for policy
         */
        LUDDecryptionKey dkSatisfy = scheme.generateDecryptionKey(msk, getFulfilling());
        LUDDecryptionKey dkNonSatisfy = scheme.generateDecryptionKey(msk, getNonFulfilling());

        /*
         * MSP for policy
         */
        MonotoneSpanProgram msp = new MonotoneSpanProgram(
                policy, new Zp(scheme.getPublicParameters().getGroupSize()));

        System.out.println("Test satisfying and non-satisfying set of attributes.");
        assertTrue(msp.isQualified(dkSatisfy.getAttributes()));
        assertFalse(msp.isQualified(dkNonSatisfy.getAttributes()));


        System.out.println("Test key elements based on bilinear maps");
        for (LUDDecryptionKey dk : new LUDDecryptionKey[]{dkSatisfy, dkNonSatisfy}) {
            HashIntoStructure hash = scheme.getPublicParameters().getPairingParameters().getHashIntoZGroupExponent();

            /*
             * Let <g,h>=<e(g1,g2),e(g1,g2)^alpha> be ElGamal public key for MSK secret key alpha. Then
             *
             * e(k0,g2)=e(g1^alpha w1^r,g2)
             *        =e(g1,g2)^alpha e(w1,g2^r)
             *        =g e(g1^d,g2^r)
             *        =g e(g1^r,g2^d)
             *        =g e(K1,w2)
             */

            /*e(k0,g2):*/
            GroupElement a = pairing.apply(dk.k0, scheme.getPublicParameters().g2);

            /*g=e(g1,g2)^alpha*/
            GroupElement b = scheme.getPublicParameters().getElgamalEncryptionKey().getH();

            /*e(K1,w2)*/
            GroupElement c = pairing.apply(dk.k1, scheme.getPublicParameters().w2);

            assertEquals(a, b.op(c));


            for (Map.Entry<Attribute, GroupElement[]> entry : dk.ki_map.entrySet()) {
                Attribute ai = entry.getKey();
                GroupElement[] k23 = entry.getValue();
                ZnElement h = (ZnElement) hash.hashIntoStructure(ai);

                /*
                 *   e(K_ai,3,g2)=
                 *  =e( (u1^H(ai) h1)^ri v1^-r,g2)
                 *  =e( u1^(ri H(ai)) h1^ri,g2) e(g1^-r,v2)
                 *  =e( u1^^(ri H(ai)),g2) e(h1^ri,g2) e(K1^-1,v2)
                 *  =e( g1^ri,u2^H(ai)) e (g1^ri,h2) e(K1^-1,v2)
                 *  =e( K_ai,2,u2^H(ai) h2) e(K1^-1,v2)
                 *  =
                 */
                a = pairing.apply(k23[1], scheme.getPublicParameters().g2);
                b = pairing.apply(k23[0], scheme.getPublicParameters().u2.pow(h).op(scheme.getPublicParameters().h2));
                c = pairing.apply(dk.k1.inv(), scheme.getPublicParameters().v2);

                assertEquals(a, b.op(c));
            }

        }
        //}
    }

    /**
     * Serialize representation, print it, de-serialize it.
     *
     * @param r - the representation
     * @return - the de-serialized representation
     */
    private Representation checkConvert(Representation r) {
        JSONConverter converter = new JSONConverter();
        String s = converter.serialize(r);
        System.out.println(s);
        Representation result = converter.deserialize(s);

        return result;
    }

    /**
     * Serialize Standalone Representable, de-serialize it, check if equals.
     *
     * @param r
     * @return
     */
    private StandaloneRepresentable checkConvertStandalone(StandaloneRepresentable r) {
        Representation in = new RepresentableRepresentation(r);
        Representation out = checkConvert(in);

        StandaloneRepresentable result =
                (StandaloneRepresentable) ((RepresentableRepresentation) out).recreateRepresentable();
        assertEquals(r, result);
        return result;

    }

    @Test
    /**
     * This test implements the whole encaps/decaps flow as required in reality.
     */
    public void testTransform() {
        Representation repr;
        /*
         * two test modes. One with serialization of each element.
         */
        for (boolean checkSerialization : new boolean[]{false, true}) {


            Zp zp = new Zp(scheme.getPublicParameters().getGroupSize());

            Policy policy = setupPolicy();

            if (checkSerialization) {
                System.out.println("Test serialization of policy:");
                policy = (Policy) checkConvertStandalone(policy);
            }
            System.out.println("Setup encryption key for policy " + policy);

            System.out.println((new JSONConverter()).serialize(policy.getRepresentation()));

            if (checkSerialization) {
                System.out.println("Test serialization of scheme:");
                scheme = (ElgamalLargeUniverseDelegationKEM) checkConvertStandalone(scheme);
            }


            LUDEncryptionKey ek = scheme.generateEncryptionKey(policy);
            if (checkSerialization) {
                repr = ek.getRepresentation();
                System.out.println("Representation of encryption key: ");
                repr = checkConvert(repr);
                LUDEncryptionKey ekprime = scheme.getEncapsulationKey(repr);
                assertEquals(ek, ekprime);
                ek = ekprime;
            }


            System.out.println("Generate symmetric key and encapsulation.");

            KeyAndCiphertext<? extends SymmetricKey> kAndCt = scheme.encaps(ek);

            SymmetricKey k = kAndCt.key;
            if (checkSerialization) {
                repr = k.getRepresentation();
                System.out.println("Representation of symmetric key: ");
                repr = checkConvert(repr);
                ByteArrayImplementation kprime = scheme.getKey(repr);
                assertEquals(k, kprime);
                k = kprime;
            }

            LUDCipherText ct = (LUDCipherText) kAndCt.encapsulatedKey;
            if (checkSerialization) {
                repr = ct.getRepresentation();
                System.out.println("Representation of ciphertext: ");
                repr = checkConvert(repr);
                LUDCipherText ctprime = scheme.getEncapsulatedKey(repr);
                assertEquals(ct, ctprime);
                ct = ctprime;
            }


            LUDDecryptionKey dkSatisfy = scheme.generateDecryptionKey(msk, getFulfilling());
            if (checkSerialization) {
                repr = dkSatisfy.getRepresentation();
                System.out.println("Representation of matching key: ");
                repr = checkConvert(repr);
                LUDDecryptionKey prime = scheme.getDecapsulationKey(repr);
                assertEquals(dkSatisfy, prime);
                dkSatisfy = prime;
            }


            LUDDecryptionKey dkNonSatisfy = scheme.generateDecryptionKey(msk, getNonFulfilling());
            if (checkSerialization) {
                repr = dkNonSatisfy.getRepresentation();
                System.out.println("Representation of non matching key: ");
                repr = checkConvert(repr);
                LUDDecryptionKey prime = scheme.getDecapsulationKey(repr);
                assertEquals(dkNonSatisfy, prime);
                dkNonSatisfy = prime;
            }

            ByteArrayImplementation kprime = scheme.decaps(ct, dkSatisfy);

            assertEquals(k, kprime);

            boolean except = false;
            try {
                kprime = scheme.decaps(ct, dkNonSatisfy);
            } catch (UnqualifiedKeyException e) {
                except = true;
            }
            assertTrue(except);


            TransformationAndDecryptionKey tkdk = scheme.generateTransformationKey(dkSatisfy);
            if (checkSerialization) {
                repr = tkdk.decryptionKey.getRepresentation();
                System.out.println("Representation of transformed decryption key: ");
                repr = checkConvert(repr);
                ElgamalPrivateKey prime = scheme.getSchemeForTransformedCiphertexts().getDecapsulationKey(repr);
                assertEquals(tkdk.decryptionKey, prime);
                tkdk.decryptionKey = prime;
            }


            ElgamalKEMCiphertext ctTransformed = scheme.transform(ct, tkdk.transformationKey);
            if (checkSerialization) {
                repr = ctTransformed.getRepresentation();
                System.out.println("Representation of transformed cipher text: ");
                repr = checkConvert(repr);
                ElgamalKEMCiphertext prime = scheme.getSchemeForTransformedCiphertexts()
                        .getEncapsulatedKey(repr);
                assertEquals(ctTransformed, prime);
                ctTransformed = prime;
            }


            kprime = scheme.getSchemeForTransformedCiphertexts().decaps(ctTransformed, tkdk.decryptionKey);

            assertEquals(k, kprime);
        }
    }


    @Test
    public void testTransKey() {


    }


    @Test
    public void testEncaps() {
        //	while(true) {
//				((BarretoNaehrigTargetGroup) scheme.getPublicParameters().getPairingParameters().getGT())
// .setNativeEnabled(false);
//				((BarretoNaehrigSourceGroup) scheme.getPublicParameters().getPairingParameters().getG1())
// .setNativeEnabled(true);
//
//				((BarretoNaehrigSourceGroup) scheme.getPublicParameters().getPairingParameters().getG2())
// .setNativeEnabled(true);

        Policy policy = setupPolicy();

        LOGGER.info("Setup encryption key for policy " + policy);

        System.out.println("Setup encryption key for policy " + policy);


        LUDEncryptionKey ek = scheme.generateEncryptionKey(policy);


        System.out.println("Generate symmetric key and encapsulation.");


        KeyAndCiphertext<? extends SymmetricKey> kAndCt = scheme.encaps(ek);

        SymmetricKey k = kAndCt.key;

        LUDCipherText ct = (LUDCipherText) kAndCt.encapsulatedKey;

        System.out.println("Test msk key escrow");

        /*
         * with <C0,C> = <g2^s,e(g1,g2)^(alpha s)> we can interpre
         * <C',C> = <e(g1,C0),C> =<e(g1,g2)^s,e(g1,g2)^(alpha s)> as Elgamal encryption for
         * public key <g,h> = <e(g1,g2),e(g1,g2)^alpha> and secret key alpha
         */

        GroupElement c1 = pairing.apply(scheme.getPublicParameters().g1, ct.c0);
        GroupElement c2 = ct.c;

        ElgamalKEMCiphertext elgamalct = new ElgamalKEMCiphertext(
                new ElgamalCipherText(c1, c2),
                ct.encaps);

        ElgamalPrivateKey elgamalsk = new ElgamalPrivateKey(
                scheme.getPublicParameters().getPairingParameters().getGT(),
                scheme.getPublicParameters().getElgamalEncryptionKey().getG(), msk.getSecretExponent());

        //((BarretoNaehrigSourceGroup) scheme.getPublicParameters().getPairingParameters().getG2()).setNativeEnabled
        // (true);

        ByteArrayImplementation kprime
                = scheme.getSchemeForTransformedCiphertexts().decaps(elgamalct, elgamalsk);

        //((BarretoNaehrigSourceGroup) scheme.getPublicParameters().getPairingParameters().getG2()).setNativeEnabled
        // (true);

        assertEquals(k, kprime);


        System.out.println("Test bilinear properties of ciphertext components C_i,2 and C_i,3");

        MonotoneSpanProgram msp = new MonotoneSpanProgram(ek.getPolicy(),
                new Zp(scheme.getPublicParameters().getGroupSize()));


        /*
         * e(g1,Ci,2)
         * =e(g1,(u2^H(rho(i)) h2)^-ti)
         * =e(g1,u^H(rho(i))^-ti e(g1,h2^-ti)
         * =e(u1^H(rho(i)),g2^-ti) e(h1,g2^-ti)
         * =e(u1^H(rho(i)) h1,C_i,3^-1)
         */
        for (Map.Entry<BigInteger, GroupElement[]> entry : ct.abeComponents.entrySet()) {
            BigInteger index = entry.getKey();
            GroupElement[] c123 = entry.getValue();
            Attribute rho_i = (Attribute) msp.getShareReceiver(index.intValue());

            ZnElement h = (ZnElement) hash.hashIntoStructure(rho_i);
            /*
             * e(g1,Ci,2)
             */
            GroupElement a = pairing.apply(scheme.getPublicParameters().g1, c123[1]);

            /*
             * e(u1^H(rho(i)) h1,C_i,3^-1)
             */
            GroupElement b = pairing.apply(scheme.getPublicParameters().u1.pow(h)
                    .op(scheme.getPublicParameters().h1), c123[2]
                    .inv());
            assertEquals(a, b);
        }


        System.out.println("check recombination of C_i,1 against C0");


        /*
         * get coefficients \omega_i for reconstructing secret such that s=\sum \omega_i \lambda_i
         */
        Map<Integer, ZpElement> solvingVector = msp.getSolvingVector(getFulfilling());

        /*
         * \prod e(g1^\omega_i,C_i,1)
         *=\prod e(g1^\omega_i,w2^\lambda_i v2^ti)
         *=\prod e(g1,w2^(\lambda_i\omega_i) v2^(ti\omega_i)
         *=\prod e(g1,w2^(\lambda_i\omega_i)) e(g1, v2^(ti\omega_i)
         *=e(w1,g2)^(\sum \lambda_i \omega_i) \prod e(v1,g2^(ti\omega_i))
         *=e(w1,g2^s) e(v1,\sum \omega_i C_i,3)
         *=e(w1,C0)  e(v1,\sum \omega_i C_i,3)
         */



        /*
         * compute \prod e(g1^\omega_i,w2^\lambda_i v2^ti)
         */
        GroupElement pairingProduct = scheme.getPublicParameters().getPairingParameters().getGT().getNeutralElement();

        /*
         * compute \sum \omega_i C_i,3
         */
        GroupElement sum = scheme.getPublicParameters().getPairingParameters().getG2().getNeutralElement();

        for (Map.Entry<Integer, ZpElement> entry : solvingVector.entrySet()) {
            Integer index = entry.getKey();
            ZpElement omega_i = entry.getValue();

            GroupElement[] c123 = ct.abeComponents.get(BigInteger.valueOf(index));

            /*
             * e(g1^\omega_i,C_i,1)
             */
            pairingProduct = pairingProduct.op(pairing.apply(
                    scheme.getPublicParameters().g1.pow(omega_i),
                    c123[0])
            );

            sum = sum.op(c123[2].pow(omega_i));

        }

        /*
         * e(w1,C0)  e(v1,\sum \omega_i C_i,3)
         */
        GroupElement b = pairing.apply(scheme.getPublicParameters().v1, sum);
        GroupElement c = pairing.apply(scheme.getPublicParameters().w1, ct.c0);
        GroupElement d = b.op(c);
        LOGGER.debug("B: " + b);
        LOGGER.debug("C: " + c);
        LOGGER.debug("D: " + d);
        LOGGER.debug("pairingProduct: " + pairingProduct);
        assertEquals(pairingProduct, d);
    }

    //}

}
