package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.interfaces.*;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.pe.*;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.*;

/**
 * Asymmetric version of the small universe ABE scheme from [Wat11], Section 3.
 * According to a note in [AgrCha17], this scheme is still secure in the asymmetric setting.
 *
 * [Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
 * expressive, efficient, and provably secure realization. In Public Key
 * Cryptography, pages 53–70. Springer, 2011
 * [AgrCha17] Shashank Agrawal and Melissa Chase. 2017. FAME: Fast Attribute-based Message Encryption.
 * In Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security (CCS ’17).
 * Association for Computing Machinery, New York, NY, USA, 665–682. DOI:https://doi.org/10.1145/3133956.3134014
 */
public class ABECPAsymSmallWat11 implements PredicateEncryptionScheme {

    /**
     * The public parameters for this CP ABE Scheme
     */
    private ABECPAsymSmallWat11PublicParameters pp;
    /**
     * Defined as Zp_{size(groupG1)}
     */
    private Zp zp;

    public ABECPAsymSmallWat11(ABECPAsymSmallWat11PublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public ABECPAsymSmallWat11(Representation repr) {
        this.pp = new ABECPAsymSmallWat11PublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    @Override
    public ABECPAsymSmallWat11CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("Not a valid plain text for this scheme: " + plainText.getClass());
        if (!(publicKey instanceof ABECPAsymSmallWat11EncryptionKey))
            throw new IllegalArgumentException("Not a valid public key for this scheme: " + plainText.getClass());

        GroupElementPlainText pt = (GroupElementPlainText) plainText;
        ABECPAsymSmallWat11EncryptionKey pk = (ABECPAsymSmallWat11EncryptionKey) publicKey;

        ZpElement s = zp.getUniformlyRandomUnit();

        GroupElement encryptionFactor = pp.getEGgAlpha().pow(s);
        // C = M \cdot e(g_1, g_2)^{\alpha s}
        GroupElement c = pt.get().op(encryptionFactor);
        // C' = g_2^s
        GroupElement cPrime = pp.getG2().pow(s);

        // compute E_i = g^{a \cdot \lambda_i} \cdot T(\rho(i))^{-s} for every attribute i
        MonotoneSpanProgram msp = new MonotoneSpanProgram(pk.getPolicy(), zp);
        Map<Integer, ZpElement> shares = msp.getShares(s);
        if (!isMonotoneSpanProgramValid(shares, msp, pp.getAttrs().size()))
            throw new IllegalArgumentException("MSP is invalid");

        Map<BigInteger, GroupElement> mapC = new HashMap<>();
        Map<BigInteger, GroupElement> mapD = new HashMap<>();

        for (Map.Entry<Integer, ZpElement> share : shares.entrySet()) {
            // the row of the share
            BigInteger i = BigInteger.valueOf(share.getKey());
            // the party linked to this share
            Attribute rhoI = (Attribute) msp.getShareReceiver(share.getKey());
            // the share /constant
            ZpElement lambdaI = share.getValue();
            ZpElement rI = zp.getUniformlyRandomUnit();
            // C_i = (g_1^a)^lambda_i * attr_{rho_i}^{-r_i}
            GroupElement cElementI = pp.getGA().pow(lambdaI).op(pp.getAttrs().get(rhoI).pow(rI).inv());
            // D_i = g_2^r_1
            GroupElement dElementI = pp.getG2().pow(rI);

            mapC.put(i, cElementI);
            mapD.put(i, dElementI);
        }

        return new ABECPAsymSmallWat11CipherText(pk.getPolicy(), c, cPrime, mapC, mapD);
    }

    @Override
    public GroupElementPlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(privateKey instanceof ABECPAsymSmallWat11DecryptionKey))
            throw new IllegalArgumentException("Not a valid private key for this scheme: " + privateKey.getClass());
        if (!(cipherText instanceof ABECPAsymSmallWat11CipherText))
            throw new IllegalArgumentException("Not a valid ciphertext for this scheme:" + cipherText.getClass());


        ABECPAsymSmallWat11CipherText c = (ABECPAsymSmallWat11CipherText) cipherText;
        ABECPAsymSmallWat11DecryptionKey sk = (ABECPAsymSmallWat11DecryptionKey) privateKey;

        MonotoneSpanProgram msp = new MonotoneSpanProgram(c.getPolicy(), zp);

        // the attributes of the decryption key
        Set<Attribute> S = sk.getMapKx().keySet();

        if (!msp.isQualified(S)) {
            throw new UnqualifiedKeyException("The given decryption key does not satisfy the MSP.");
        }

        GroupElement message = c.getC();

        List<GroupElement> zList = new ArrayList<>();

        for (Map.Entry<Integer, ZpElement> omegaI : msp.getSolvingVector(S).entrySet()) {
            // the row of the share
            BigInteger i = BigInteger.valueOf(omegaI.getKey());
            // the party linked to this share
            Attribute rhoI = (Attribute) msp.getShareReceiver(omegaI.getKey());

            if (!omegaI.getValue().getInteger().equals(BigInteger.ZERO)) {
                GroupElement cElementI = c.getMapC().get(i);
                GroupElement dElementI = c.getMapD().get(i);
                GroupElement kElementRhoI = sk.getMapKx().get(rhoI);

                GroupElement map1 = pp.getE().apply(cElementI, sk.getL());
                GroupElement map2 = pp.getE().apply(dElementI, kElementRhoI);

                map1 = map1.op(map2);
                map1 = map1.pow(omegaI.getValue().getInteger());
                zList.add(map1);
            }
        }
        // TODO: Use multiexponentiation here
        Optional<GroupElement> reduced = zList.stream().parallel().reduce(GroupElement::op);
        GroupElement tmp = pp.getE().getGT().getNeutralElement();
        if (reduced.isPresent()) {
            tmp = reduced.get();
        }

        GroupElement map = pp.getE().apply(c.getCPrime(), sk.getK());
        map = map.op(tmp.inv());
        return new GroupElementPlainText(message.op(map.inv()));

    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return null;
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return null;
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return null;
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return null;
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return null;
    }

    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof ABECPAsymSmallWat11MasterSecret))
            throw new IllegalArgumentException("The master secret is not a valid master secret for this scheme: "
                    + msk.getClass());
        if (!(kind instanceof SetOfAttributes))
            throw new IllegalArgumentException("Expected SetOfAttributes as KeyIndex but got " + kind.getClass());

        SetOfAttributes attributes = (SetOfAttributes) kind;
        ABECPAsymSmallWat11MasterSecret cpmsk = (ABECPAsymSmallWat11MasterSecret) msk;
        GroupElement gAlpha = cpmsk.get();

        Zp.ZpElement t = zp.getUniformlyRandomUnit();
        // K = gAlpha * (g1^{at})
        GroupElement k = gAlpha.op(pp.getGA().pow(t));
        // L = g2^t
        GroupElement l = pp.getG2().pow(t);

        Map<Attribute, GroupElement> mapKx = new HashMap<>();
        // \forall x in attributes : Kx = h_x^t
        for (Attribute x : attributes) {
            GroupElement kx = pp.getAttrs().get(x).pow(t);
            mapKx.put(x, kx);
        }
        return new ABECPAsymSmallWat11DecryptionKey(k, l, mapKx);
    }

    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof Policy))
            throw new IllegalArgumentException("Policy expected as CiphertextIndex");
        Policy policy = (Policy) cind;
        return new ABECPAsymSmallWat11EncryptionKey(policy);
    }

    @Override
    public Predicate getPredicate() {
        return null;
    }

    @Override
    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    private boolean isMonotoneSpanProgramValid(Map<Integer, ZpElement> shares, MonotoneSpanProgram msp, int l_max) {
        // check for line count
        if (shares.size() > l_max) {
            return false;
        } else {
            Set<Attribute> attributes = new HashSet<>();
            for (Map.Entry<Integer, ZpElement> share : shares.entrySet()) {
                if (attributes.contains((Attribute) msp.getShareReceiver(share.getKey()))) {
                    return false;
                } else {
                    attributes.add((Attribute) msp.getShareReceiver(share.getKey()));
                }
            }
            return true;
        }
    }
}
