package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPrivateKey;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.*;
import de.upb.crypto.craco.interfaces.abe.AbePredicate;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.pe.*;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.proxy.DelegatedPartialDecapsulationScheme;
import de.upb.crypto.craco.interfaces.proxy.TransformationKey;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEM;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEM.KeyAndCiphertextAndNonce;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEMCiphertext;
import de.upb.crypto.math.expressions.exponent.ExponentConstantExpr;
import de.upb.crypto.math.expressions.group.*;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.*;
import de.upb.crypto.math.serialization.util.RepresentationUtil;
import de.upb.crypto.math.structures.zn.HashIntoZn;
import de.upb.crypto.math.structures.zn.Zn.ZnElement;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;
import org.apache.log4j.Logger;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

/**
 * This class implements the ABE cipher text policy KEM with outsourcing from [1].
 * <p>
 * The scheme uses an ElGamal KEM as base and adds ABE specific functionality to it.
 * <p>
 * [1] Blömer J., Günther P., Krummel V., Löken N. (2018) Attribute-Based Encryption as a Service for Access Control
 * in Large-Scale Organizations. In: Foundations and Practice of Security. FPS 2017. Lecture Notes in Computer Science,
 * vol 10723. Springer, Cham.
 *
 * @author peter.guenther
 */

public class ElgamalLargeUniverseDelegationKEM
        implements PredicateKEM<SymmetricKey>, DelegatedPartialDecapsulationScheme<SymmetricKey> {
    private static final Logger LOGGER = Logger.getLogger(ElgamalLargeUniverseDelegationKEM.class.getName());

    private final LUDPublicParameters pp;


    public ElgamalLargeUniverseDelegationKEM(LUDPublicParameters pp) {
        this.pp = pp;

    }

    public ElgamalLargeUniverseDelegationKEM(Representation r) {
        this.pp = new LUDPublicParameters(r);
    }

    public LUDPublicParameters getPublicParameters() {
        return pp;
    }

    @Override
    public KeyAndCiphertext<SymmetricKey> encaps(
            EncryptionKey pk) {
        if (!(pk instanceof LUDEncryptionKey))
            throw new IllegalArgumentException("Not a valid Encryption Key for this scheme");

        /*
         * ciphertext components are all in G2, fetch elements from G2
         */
        GroupElement w = this.getPublicParameters().w2;
        GroupElement v = this.getPublicParameters().v2;
        GroupElement u = this.getPublicParameters().u2;
        GroupElement h = this.getPublicParameters().h2;
        GroupElement g = this.getPublicParameters().g2;


        BigInteger p = this.getPublicParameters().getPairingParameters().getG2().size();
        Zp zp = new Zp(p);
        HashIntoStructure hashToZp = new HashIntoZn(p);


        LUDEncryptionKey ek = (LUDEncryptionKey) pk;

        /*
         * generate encapsulation in GT for public key <e(g1,g2),e(g1,g2)^alpha> with nonce s and Random message R:
         * <c1,c2> = <e(g1,g2)^s,R e(g1,g2)^alpha s>
         */
        KeyAndCiphertextAndNonce kcn = pp.getBaseKEM().encaps_internal(pp.getElgamalEncryptionKey());
        BigInteger s = kcn.nonce;

        /*
         * we need additional element s blinded in g2
         */
        GroupElement c0 = g.pow(s);


        MonotoneSpanProgram msp = new MonotoneSpanProgram(ek.getPolicy(), zp);

        /*
         * now share nonce with ABE scheme for given policy (encoded into MSP)
         */
        Map<Integer, ZpElement> shares = msp.getShares(zp.createZnElement(s));

        Map<BigInteger, GroupElement[]> ciphertextComponents = new HashMap<>();
        for (Entry<Integer, ZpElement> share : shares.entrySet()) {
            // line number
            BigInteger i = BigInteger.valueOf(share.getKey());
            // corresponding attribute \rho(i)
            Attribute rho_i = (Attribute) msp.getShareReceiver(share.getKey());

            // corresponding element in G1
            ZnElement hash = (ZnElement) hashToZp.hashIntoStructure(rho_i);

            /*
             * share of s corresponding to this index
             */
            ZpElement lambda_i = share.getValue();

            ZpElement ti = zp.getUniformlyRandomElement();

            GroupElement[] Ci = new GroupElement[3];

            /*
             * C_i,1=w2^lambda_i v2^ti
             */
            Ci[0] = w.pow(lambda_i).op(v.pow(ti));

            /*
             * C_i,2=(u2^H(\rho(i)) h2)^-ti
             */
            Ci[1] = u.pow(hash).op(h).pow(ti).inv();

            /*
             * C_i,3=g2^ti
             */
            Ci[2] = g.pow(ti);

            ciphertextComponents.put(i, Ci);
        }

        /*
         * setup the ABE ciphertext based on the Elgamal Ciphertext and the ABE shares
         */
        LUDCipherText ct = new LUDCipherText(
                ek.getPolicy(),
                (ElgamalKEMCiphertext) kcn.keyAndCiphertext.encapsulatedKey,
                c0,
                ciphertextComponents);
        LOGGER.trace("C: " + ct);

        KeyAndCiphertext<SymmetricKey> result = new KeyAndCiphertext<SymmetricKey>();
        result.encapsulatedKey = ct;
        result.key = kcn.keyAndCiphertext.key;
        return result;
    }

    @Override
    public ByteArrayImplementation decaps(CipherText encapsulatedKey, DecryptionKey sk) throws UnqualifiedKeyException {

        /*generic implementation. Not efficient but adds maybe some SCA resistance*/
//		TransformationAndDecryptionKey tkdk = this.generateTransformationKey(sk);
//		CipherText ctTransformed = this.transform(encapsulatedKey, tkdk.transformationKey);
//		return this.getSchemeForTransformedCiphertexts().decaps(ctTransformed, tkdk.decryptionKey);


        /*generate dummy transformation key with secret exponent 1*/
        TransformationAndDecryptionKey tkAndDk = this.generateTransformationKey(sk, BigInteger.ONE);
        //To generate test data of decaps, use this:
        //TransformationAndDecryptionKey tkAndDk = this.generateTransformationKey(sk, BigInteger.valueOf(23));
        CipherText ctTransformed = this.transform(encapsulatedKey, tkAndDk.transformationKey);
        /*
         * construct elgamal key for generator e(g1,g2)^alpha and secret key 1
         */

//		ElgamalPrivateKey egsk = new ElgamalPrivateKey(
//				getPublicParameters().getPairingParameters().getGT(), 
//				getPublicParameters().getElgamalEncryptionKey().getH(), 
//				new Zp(getPublicParameters().getGroupSize()).getOneElement());
        return this.getSchemeForTransformedCiphertexts().decaps(ctTransformed, tkAndDk.decryptionKey);


//		System.out.println((new JSONConverter()).serialize(ctTransformed.getRepresentation()));
//		System.out.println(((ElgamalKEMCiphertext) ctTransformed).getSymmetricEncryption());
//		String s: 
//		for(byte b : ((ElgamalKEMCiphertext) ctTransformed).getSymmetricEncryption().getData()){
//			}

    }


    @Override
    public ElgamalKEMCiphertext transform(CipherText original,
                                          TransformationKey transformKey) throws UnqualifiedKeyException {
        if (!(transformKey instanceof LUDDecryptionKey))
            throw new IllegalArgumentException("Not a valid transformation key for this scheme");
        if (!(original instanceof LUDCipherText))
            throw new IllegalArgumentException("Not a valid ciphertext for this scheme");

        LUDDecryptionKey tk = (LUDDecryptionKey) transformKey;
        LUDCipherText ct = (LUDCipherText) original;


        BilinearMap pairing = this.getPublicParameters().getPairingParameters().getBilinearMap();

        Zp zp = new Zp(this.getPublicParameters().getPairingParameters().getG2().size());


        MonotoneSpanProgram msp = new MonotoneSpanProgram(ct.policy, zp);

        Map<Attribute, GroupElement[]> ki_map = tk.ki_map;

        Set<Attribute> attributes = ki_map.keySet();

        /*check if attributes of transformation key fulfill policy of ciphertext*/
        if (!this.checkPredicate(tk.getKeyIndex(), ct.getPolicy()))
            throw new UnqualifiedKeyException(
                    "The given transformation key does not satisfy the ciphertext's policy");

        //List<GroupElement> zList = new ArrayList<GroupElement>();
        Map<Integer, ZpElement> solvingVector = msp.getSolvingVector(attributes);


        /*store pairing product to do batch processing*/
        // PairingProductExpression expr = pairing.pairingProductExpression();

        /*
         * e(K0,C0)^1
         */
        // expr.op(tk.k0, ct.c0);

        GroupElementExpression expr = new PairingExpr(
                pairing,
                tk.k0.expr(),
                ct.c0.expr()
        );

        /*
         * compute product over \prod e(K1,C_i,1)^bi as sum e(K1,\sum C_i,1)^bi
         */
        GroupElement ci1Sum = this.getPublicParameters().getPairingParameters().getG2()
                .getNeutralElement();

        /*
         * compute pairing product over supporting set of share
         */
        for (Entry<Integer, ZpElement> omega : solvingVector.entrySet()) {
            /*
             * get lagrange coefficient of share lambda
             */
            ZpElement b_i = omega.getValue();

            /*
             * get corresponding attribute
             */
            BigInteger i = BigInteger.valueOf(omega.getKey());
            Attribute rho_i = (Attribute) msp.getShareReceiver(omega.getKey());

            /*
             *   \sum C_i,1
             */
            ci1Sum = ci1Sum.op(ct.abeComponents.get(i)[0].pow(b_i));

            /*
             * e(K_rho(i),2  ; C_i,2)^-bi=e(-K_rho(i),2  ; C_i,2)^bi
             *
             * bi is typically small, hence we prefer to use bilinearity to pull sign into first argument
             */
            expr = expr.opPow(
                    new PairingExpr(
                            pairing,
                            tk.ki_map.get(rho_i)[0].inv().expr(),
                            ct.abeComponents.get(i)[1].expr()
                    ),
                    b_i
            );
            //expr.op(tk.ki_map.get(rho_i)[0].inv(), ct.abeComponents.get(i)[1], b_i);

            /*
             * e(K_rho(i),3  ; C_i,3)^-bi=e(-K_rho(i),3  ; C_i,3)^bi
             */
            expr = expr.opPow(
                    new PairingExpr(
                            pairing,
                            tk.ki_map.get(rho_i)[1].inv().expr(),
                            ct.abeComponents.get(i)[2].expr()
                    ),
                    b_i
            );
            // expr.op(tk.ki_map.get(rho_i)[1].inv(), ct.abeComponents.get(i)[2], b_i);


//			assertEquals(pairing.apply(tk.k1,ct.abeKomponents.get(i)[0]),
//						pairing.apply(, u).op(pairing.apply(t, u))
//					);
        }


        /*
         * e(K1,\sum C_i,1)^-bi
         */
        expr = expr.op(
                new PairingExpr(
                        pairing,
                        tk.k1.inv().expr(),
                        ci1Sum.expr()
                )
        );
        //expr.op(tk.k1.inv(), ci1Sum);

        GroupElement b = expr.evaluate();

        //	assertEquals(b,this.getPublicParameters().getElgamalEncryptionKey().getH());
        //	System.out.println("B=" + b);

        return new ElgamalKEMCiphertext(
                new ElgamalCipherText(b, ct.c),
                ct.encaps
        );
    }


    @Override
    public TransformationAndDecryptionKey generateTransformationKey(
            DecryptionKey original) {
        Zp zp = new Zp(this.getPublicParameters().getGroupSize());
        /*get blinding for ElGamal private key*/
        ZnElement z = zp.getUniformlyRandomElement();

        return generateTransformationKey(original, z.getInteger());
    }

    public TransformationAndDecryptionKey generateTransformationKey(
            DecryptionKey original, BigInteger blinding) {

        Zp zp = new Zp(this.getPublicParameters().getGroupSize());

        ZnElement z = zp.valueOf(blinding);

        /* this part is confusing but it has to be like this to pass CCA test in Elgamal decaps
         *  generate ElGamal private key 1/z with public key <g',h'> = <e(g1,g2)^alpha z,e(g1,g2)^alpha>
         *  this ensures, that re-encryption a ciphertext <e(g1,g2)^(alpha s z), R e(g1,g2)^(alpha s)>
         *  with <g',h'> and reconstructed nonce s results in the same ciphertext.
         *
         *   If we would instead set
         *   <g',h'> = <e(g1,g2)^alpha ,e(g1,g2)^alpha/z>, we would obtain the ciphertext
         *   <e(g1,g2)^(alpha s), R e(g1,g2)^alpha/z s> and the CCA check fails.
         */
        ElgamalPrivateKey elgamalDecryptionKey = new ElgamalPrivateKey(
                this.getPublicParameters().getPairingParameters().getGT(),
                //here, the following key is given as <g,h>=<e(g1,g2),e(g1,g2)^alpha>
                this.getPublicParameters().getElgamalEncryptionKey().getH().pow(z),
                z.inv(),
                this.getPublicParameters().getElgamalEncryptionKey().getH()
        );


        /*
         * Now blind each key komponent with z. Using this transformed key results in elgamal encryption for secret
         * key 1/z.
         */
        LUDDecryptionKey dk = (LUDDecryptionKey) original;

        GroupElement k0 = dk.k0.pow(z);
        GroupElement k1 = dk.k1.pow(z);

        Map<Attribute, GroupElement[]> transmap = dk.ki_map;

        Map<Attribute, GroupElement[]> map = new HashMap<>();

        for (Map.Entry<Attribute, GroupElement[]> entry : transmap.entrySet()) {
            GroupElement k23[] = new GroupElement[2];
            k23[0] = entry.getValue()[0].pow(z);
            k23[1] = entry.getValue()[1].pow(z);
            map.put(entry.getKey(), k23);
        }


        LUDDecryptionKey tk = new LUDDecryptionKey(k0, k1, map);

        TransformationAndDecryptionKey result = new TransformationAndDecryptionKey();
        result.decryptionKey = elgamalDecryptionKey;
        result.transformationKey = tk;
        return result;
    }

    @Override
    public ElgamalKEM getSchemeForTransformedCiphertexts() {
        return pp.getBaseKEM();
    }


    @Override
    public LUDDecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof LUDMasterSecret))
            throw new IllegalArgumentException("Not a valid MasterSecret for this scheme");
        if (!(kind instanceof SetOfAttributes))
            throw new IllegalArgumentException("SetOfAttributes expected as KeyIndex");

        LUDMasterSecret ludMsk = (LUDMasterSecret) msk;

        SetOfAttributes attributes = (SetOfAttributes) kind;

        Map<Attribute, GroupElement[]> map = new HashMap<>();

        Zp zp = new Zp(this.getPublicParameters().getPairingParameters().getG1().size());

        //choose random, set to one for debugging
        //ZpElement r = zp.getOneElement();
        ZpElement r = zp.getUniformlyRandomElement();

        ZpElement alpha = ludMsk.getSecretExponent();

        /*
         * K0=g1^alpha w1^r
         * K1=v1^-r
         * K_ai,2=g1^r_ai
         * K_ai,3=(u1^H(ai) h1)^r_ai v1^-r
         */
        GroupElement K0 = this.getPublicParameters().g1.pow(alpha)
                .op(this.getPublicParameters().w1.pow(r));


        GroupElement K1 = this.getPublicParameters().g1.pow(r);

        HashIntoStructure hashIntoExponent = new HashIntoZn(zp.getCharacteristic());

        for (Attribute ai : attributes) {
            GroupElement[] k23 = new GroupElement[2];
            ZpElement ri = zp.getUniformlyRandomElement();
            k23[0] = this.getPublicParameters().g1.pow(ri);
            k23[1] = this.getPublicParameters().u1.pow((ZnElement) hashIntoExponent.hashIntoStructure(ai))
                    .op(this.getPublicParameters().h1).pow(ri)
                    .op(this.getPublicParameters().v1.pow(r.neg()));
            map.put(ai, k23);

        }

        return new LUDDecryptionKey(K0, K1, map);

    }

    @Override
    public LUDEncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof Policy))
            throw new IllegalArgumentException("Policy as CiphertextIndex expected");
        return new LUDEncryptionKey((Policy) cind);
    }

    /**
     * {@inheritDoc}
     * <p>
     * This scheme uses a {@link Policy} as the CipherTextIndex and a
     * {@link SetOfAttributes} as the KeyIndex.
     */
    @Override
    public Predicate getPredicate() {
        return new AbePredicate();
    }


    @Override
    public Representation getRepresentation() {
        return this.getPublicParameters().getRepresentation();
    }


    @Override
    public LUDDecryptionKey recreateTransformationKey(Representation repr) {
        return this.getDecapsulationKey(repr);
    }


    @Override
    public LUDMasterSecret getMasterSecret(Representation repr) {
        ZpElement alpha = (new Zp(this.getPublicParameters().getGroupSize())).getElement(repr);
        return new LUDMasterSecret(alpha);
    }

    public ByteArrayImplementation getKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }


    @Override
    public LUDCipherText getEncapsulatedKey(Representation repr) {
        LUDCipherText result = new LUDCipherText();
        ObjectRepresentation or = (ObjectRepresentation) repr;
        RepresentationUtil.restoreStandaloneRepresentable(result, or, "policy");
        RepresentationUtil.restoreStandaloneRepresentable(result, or, "encaps");

        Group group2 = this.getPublicParameters().getPairingParameters().getG2();
        Group targetGroup = this.getPublicParameters().getPairingParameters().getGT();

        RepresentationUtil.restoreElement(result, or, "c0", group2);
        RepresentationUtil.restoreElement(result, or, "c", targetGroup);

        Map<BigInteger, GroupElement[]> map = new HashMap<>();

        /*
         * recreate map with attribute based key components.
         */
        MapRepresentation mr = (MapRepresentation) or.get("abeComponents");

        for (Map.Entry<Representation, Representation> entry : mr.getMap().entrySet()) {
            BigInteger i = ((BigIntegerRepresentation) entry.getKey()).get();

            ListRepresentation lr = ((ListRepresentation) entry.getValue());
            ArrayList<GroupElement> list = new ArrayList<GroupElement>();

            for (Representation er : lr) {
                list.add(group2.getElement(er));
            }


            map.put(i, list.toArray(new GroupElement[list.size()]));
        }
        result.setAbeComponents(map);
        return result;
    }

    @Override
    public LUDEncryptionKey getEncapsulationKey(Representation repr) {
        return new LUDEncryptionKey(repr);
    }


    @Override
    public LUDDecryptionKey getDecapsulationKey(Representation repr) {

        ObjectRepresentation or = (ObjectRepresentation) repr;
        Group G1 = this.getPublicParameters().getPairingParameters().getG1();
        GroupElement k0 = G1.getElement(or.get("k0"));
        GroupElement k1 = G1.getElement(or.get("k1"));
        Map<Attribute, List<GroupElement>> map = new HashMap<>();
        map = RepresentationUtil.recreateMapOfLists(or.get("map"), G1);
        Map<Attribute, GroupElement[]> elementmap = new HashMap<>();
        /*
         * recreate map with attribute based key components.
         * TODO: try to implement generic method
         */
        for (Map.Entry<Attribute, List<GroupElement>> entry : map.entrySet()) {
            GroupElement[] list = new GroupElement[entry.getValue().size()];
            int i = 0;
            for (GroupElement elem : entry.getValue()) {
                list[i] = elem;
                i++;
            }
            elementmap.put(entry.getKey(), list);
        }

        return new LUDDecryptionKey(k0, k1, elementmap);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof ElgamalLargeUniverseDelegationKEM))
            return false;
        ElgamalLargeUniverseDelegationKEM other = (ElgamalLargeUniverseDelegationKEM) obj;
        if (pp == null) {
            if (other.pp != null)
                return false;
        } else if (!pp.equals(other.pp))
            return false;
        return true;
    }


}
