package de.upb.crypto.craco.abe.fuzzy.small;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.abe.accessStructure.exception.NoSatisfyingSet;
import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.craco.abe.fuzzy.large.Identity;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.interfaces.pe.*;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Fuzzy IBE with MSP.
 * <p>
 * The implementation of the construction presented in Section 3.2
 * <p>
 * Abstract: Fuzzy Identity-Based Encryption (Fuzzy IBE) denotes an ABE scheme
 * with a specific access policy. The key generation and the encryption
 * algorithm receive a set of attributes ! and !0. The decryption algorithm
 * yields the original plaintext m if ! and !0 have at least d attributes in
 * common. We now define the small and the large universe construction for Fuzzy
 * IBE. The constructions were published by Sahai and Waters [SW05]. We adjusted
 * the security proofs of the constructions to the security proof framework in
 * Section 3.1.2.6. Moreover, we changed the security assumption for the proof
 * of the small universe construction. In the original paper, Sahai and Waters
 * defined an own security assumption for this construction. This assumption is
 * not a standard assumption and, to the best of our knowledge, has not been
 * examined further. We therefore use the well-known DBDH assumption to prove
 * the security of this construction. For the large universe construction, we
 * removed a parameter from the public parameters that is not needed.
 * Furthermore, we dropped a factor of the Waters function T (x) that has no
 * influence on the security of the construction. Lastly, we present a
 * modification for the decryption algorithm of the large universe construction.
 * This modification was published by Piretti et. al. in 2006 [PTMW06].
 * <p>
 * [SW05] Amit Sahai and Brent Waters. Fuzzy identity-based encryption. In
 * Ronald Cramer, editor, Advances in Cryptology – EUROCRYPT 2005, volume 3494
 * of Lecture Notes in Computer Science, pages 457–473. Springer Berlin
 * Heidelberg, 2005.
 * <p>
 * [PTMW06] Matthew Pirretti,Patrick Traynor,Patrick McDaniel,and BrentWaters.
 * Secure attribute-based systems. In Proceedings of the 13th ACM conference on
 * Computer and communications security, CCS ’06, pages 99–112, New York, NY,
 * USA, 2006. ACM.
 *
 * @author Marius Dransfeld, Fabian Eidens, Refactoring: Mirko Jürgens
 */
public class IBEFuzzySW05Small implements PredicateEncryptionScheme {

    /**
     * The public parameters of this scheme.
     */
    private IBEFuzzySW05SmallPublicParameters pp;
    /**
     * Defined as Z_{size(G1)}, where G1 is defined in the public parameters.
     */
    private Zp zp;

    /**
     * Default constructor.
     */
    public IBEFuzzySW05Small(IBEFuzzySW05SmallPublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public IBEFuzzySW05Small(Representation repr) {
        this.pp = new IBEFuzzySW05SmallPublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("Not a valid plain text for this scheme");

        if (!(publicKey instanceof IBEFuzzySW05SmallEncryptionKey))
            throw new IllegalArgumentException("Not a valid public key for this scheme");

        GroupElementPlainText pt = (GroupElementPlainText) plainText;
        IBEFuzzySW05SmallEncryptionKey pk = (IBEFuzzySW05SmallEncryptionKey) publicKey;
        // s <- Zp
        ZpElement s = zp.getUniformlyRandomUnit();
        // the attributes of the public key
        SetOfAttributes identity = pk.getIdentity();
        // E_prime = m*Y^s
        GroupElement e_prime = pt.get().op(pp.getY().pow(s));

        Map<Attribute, GroupElement> e_map = new HashMap<>();
        // for all attributes i in the public key : E_i = T_(i-1)^s
        for (Attribute i : identity) {
            GroupElement e_i = pp.getT().get(i).pow(s);
            e_map.put(i, e_i);
        }
        return new IBEFuzzySW05SmallCipherText(identity, e_prime, e_map);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof IBEFuzzySW05SmallCipherText))
            throw new IllegalArgumentException("Not a valid cipher text for this scheme");

        if (!(privateKey instanceof IBEFuzzySW05SmallDecryptionKey))
            throw new IllegalArgumentException("Not a valid private key for this scheme");

        IBEFuzzySW05SmallCipherText ct = (IBEFuzzySW05SmallCipherText) cipherText;
        IBEFuzzySW05SmallDecryptionKey sk = (IBEFuzzySW05SmallDecryptionKey) privateKey;

        ThresholdPolicy policy = new ThresholdPolicy(pp.getD().intValue(), sk.getIdentity());
        // the msp of the private key
        MonotoneSpanProgram msp = new MonotoneSpanProgram(policy, zp);

        // the shares of the private key
        Map<BigInteger, GroupElement> d = sk.getD();

        GroupElement tmp = pp.getGroupGT().getNeutralElement();
        Map<Integer, ZpElement> solvingVector = null;
        // vector v, so that v * M = S
        try {
            solvingVector = msp.getSolvingVector(ct.getOmega_prime());
        } catch (NoSatisfyingSet e) {
            throw new UnqualifiedKeyException("The given key does not solve the msp");
        }
        try {
            for (Entry<Integer, ZpElement> a : solvingVector.entrySet()) {
                // row number
                BigInteger i = BigInteger.valueOf(a.getKey());
                // the attribute of this row number
                Attribute rho_i = (Attribute) msp.getShareReceiver(a.getKey());
                // the result of alpha * row_i = S_i
                BigInteger alpha = a.getValue().getInteger();
                if (!alpha.equals(BigInteger.ZERO)) {
                    tmp = tmp.op(pp.getE().apply(d.get(i), ct.getE().get(rho_i).pow(alpha)));
                }
            }
        } catch (NullPointerException e) {
            throw new WrongAccessStructureException("The attributes provided in the identity are not in the universe.");
        }

        return new GroupElementPlainText(ct.getE_prime().op(tmp.inv()));

    }

    @Override
    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new GroupElementPlainText(repr, pp.getGroupGT());
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new IBEFuzzySW05SmallCipherText(repr, pp);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new IBEFuzzySW05SmallEncryptionKey(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new IBEFuzzySW05SmallDecryptionKey(repr, pp);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        result = prime * result + ((zp == null) ? 0 : zp.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof IBEFuzzySW05Small) {
            IBEFuzzySW05Small other = (IBEFuzzySW05Small) o;
            return pp.equals(other.pp);
        } else {
            return false;
        }
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return new IBEFuzzySW05SmallMasterSecret(repr, pp);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Generates an {@link DecryptionKey} out of the given {@link Identity}.
     * This {@link DecryptionKey} can only decrypt cipher texts if there are at
     * least {@link IBEFuzzySW05SmallPublicParameters#getD()} attributes in the
     * intersection of this {@link Identity} and the {@link Identity} of the
     * respective {@link EncryptionKey}.
     */
    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(kind instanceof SetOfAttributes))
            throw new IllegalArgumentException("Identity expected as KeyIndex");
        if (!(msk instanceof IBEFuzzySW05SmallMasterSecret))
            throw new IllegalArgumentException("Not a valid master secret for this scheme");

        IBEFuzzySW05SmallMasterSecret masterSecret = (IBEFuzzySW05SmallMasterSecret) msk;
        SetOfAttributes id = (SetOfAttributes) kind;

        ThresholdPolicy policy = new ThresholdPolicy(pp.getD().intValue(), id);
        MonotoneSpanProgram msp = new MonotoneSpanProgram(policy, zp);

        Map<BigInteger, GroupElement> d = new HashMap<>();

        // M * v = shares (where v is a vector v = (k, r_2,...) r_2, .. <- Zp
        // and v * e = y
        Map<Integer, ZpElement> shares = msp.getShares(masterSecret.getY());
        try {
            for (Entry<Integer, ZpElement> share : shares.entrySet()) {
                // share for attribute i (row number)
                int i = share.getKey();
                // attribute described by row i
                Attribute rho_i = (Attribute) msp.getShareReceiver(share.getKey());

                // row i * v (see above)
                ZpElement m_i_u = share.getValue();
                // t_p_i = t_(rho_i - 1)
                ZpElement t_p_i = masterSecret.getT().get(rho_i);
                // M_i_u = M_i_u / t_p_i
                m_i_u = (ZpElement) m_i_u.div(t_p_i);
                // D_i = g^M_i_u
                d.put(BigInteger.valueOf(i), pp.getG().pow(m_i_u.getInteger()));
            }
        } catch (NullPointerException e) {
            throw new WrongAccessStructureException("The attributes provided in the identity are not in the universe.");
        }
        return new IBEFuzzySW05SmallDecryptionKey(id, d);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Generates an {@link EncryptionKey} out of the given {@link Identity}.
     * Plain texts encrypted by this {@link EncryptionKey} can only be decrypted
     * if there are at least {@link IBEFuzzySW05SmallPublicParameters#getD()} attributes
     * in the intersection of this {@link Identity} and the {@link Identity} of
     * the respective {@link DecryptionKey}.
     */
    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof SetOfAttributes))
            throw new IllegalArgumentException("Identity expected as CiphertextIndex");
        SetOfAttributes identity = (SetOfAttributes) cind;
        return new IBEFuzzySW05SmallEncryptionKey(identity);
    }

    /**
     * {@inheritDoc}
     * <p>
     * This scheme uses a {@link Identity} as {@link KeyIndex} and
     * {@link CiphertextIndex}. The {@link Predicate} is that there are at least
     * {@link IBEFuzzySW05SmallPublicParameters#getD()} attributes in the intersection.
     */
    @Override
    public Predicate getPredicate() {
        return new Predicate() {

            @Override
            public boolean check(KeyIndex kind, CiphertextIndex cind) {
                if (!(kind instanceof SetOfAttributes))
                    throw new IllegalArgumentException("SetOfAttributes expected as KeyIndex");
                if (!(cind instanceof SetOfAttributes))
                    throw new IllegalArgumentException("SetOfAttributes expceted as CiphertextIndex");
                SetOfAttributes iCind = (SetOfAttributes) cind;
                SetOfAttributes iKind = (SetOfAttributes) kind;
                iCind.retainAll(iKind);
                return iCind.size() >= pp.getD().intValue();
            }
        };
    }

    public IBEFuzzySW05SmallPublicParameters getPublicParameters() {
        return pp;
    }

}
