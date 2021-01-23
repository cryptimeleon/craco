package de.upb.crypto.craco.abe.cp.large;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.UnqualifiedKeyException;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.common.interfaces.pe.Predicate;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.kem.abe.cp.large.ABECPWat11KEM;
import de.upb.crypto.craco.kem.abe.cp.large.ABECPWat11KEMCipherText;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Combines the shared functionality of {@link ABECPWat11} and
 * {@link ABECPWat11KEM}. It is a generalization of the former to reuse shared parts
 * of the implementation.
 */
public abstract class AbstractABECPWat11 {

    /**
     * The public parameters of this scheme.
     */
    @Represented
    protected ABECPWat11PublicParameters pp;

    /**
     * Efficiency reasons
     */
    protected Zp zp;

    public AbstractABECPWat11(ABECPWat11PublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public AbstractABECPWat11(Representation repr) {
        new ReprUtil(this).deserialize(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    /**
     * Computes {@code eElementMap} for {@link ABECPWat11KEMCipherText}. It is part of {@link ABECPWat11CipherText} and
     * {@link ABECPWat11KEMCipherText}.
     *
     * @param s      random element used in the encryption
     * @param msp    monotone span program corresponding to the encryption key's policy
     * @param shares shares obtained by the linear secret sharing implemented by the {@code msp}
     * @return {@code E_i = g^{a \cdot \lambda_i} \cdot T(\rho(i))^{-s}} for every attribute i
     */
    protected Map<BigInteger, GroupElement> computeE(Zp.ZpElement s, MonotoneSpanProgram msp,
                                                     Map<Integer, Zp.ZpElement> shares) {

        // index i of share s_i
        Function<Map.Entry<Integer, Zp.ZpElement>, BigInteger> keyMapper = entry -> BigInteger.valueOf(entry.getKey());

        Function<Map.Entry<Integer, Zp.ZpElement>, GroupElement> valueMapper = entry -> {
            // rho_i = share holder of attribute i
            Attribute rhoi = (Attribute) msp.getShareReceiver(entry.getKey());

            // hash of rho_i to group G_1, T(\rho(i))
            GroupElement rhoiElement = pp.getHashToG1().hash(rhoi);
            // share lambda_i
            Zp.ZpElement lambdai = entry.getValue();

            // element E_i = g^{a \cdot \lambda_i} \cdot T(\rho(i))^{-s}
            return pp.getgA().pow(lambdai).op(rhoiElement.pow(s).inv()).compute();
        };

        return shares.entrySet().parallelStream().collect(Collectors.toConcurrentMap(keyMapper, valueMapper));
    }

    /**
     * Restores {@code Y^s} used to encrypt a message M in
     * {@link ABECPWat11#encrypt(PlainText, EncryptionKey)}. Y is defined in {@link ABECPWat11Setup} as
     * {@code e(g,g)^y} for a pairing e, generator g and master secret y.
     * <p>
     * For more information see {@link ABECPWat11#encrypt(PlainText, EncryptionKey)} and {@link ABECPWat11Setup}.
     *
     * @param sk Decryption key
     * @param c  {@link ABECPWat11KEMCipherText} suffices at this point since the recovery of only requires
     *           {@code eTwoPrime} from {@link ABECPWat11KEMCipherText} and {@code eElementMap} from 
     *           {@link ABECPWat11KEMCipherText}. 
     *           Therefore this message also can be used in {@link ABECPWat11KEM}.
     * @return {@code Y^s = e(g,g)^{ys}}
     */
    protected GroupElement restoreYs(ABECPWat11DecryptionKey sk, ABECPWat11KEMCipherText c) {
        GroupElement dPrime = sk.getD_prime();
        GroupElement dTwoPrime = sk.getD_prime2();
        Map<Attribute, GroupElement> d = sk.getD();

        MonotoneSpanProgram msp = new MonotoneSpanProgram(c.getPolicy(), zp);
        Set<Attribute> attributeSetS = d.keySet();

        if (!msp.isQualified(attributeSetS))
            throw new UnqualifiedKeyException("The given private key does not satisfy the MSP");

        Map<Integer, Zp.ZpElement> solvingVector = msp.getSolvingVector(attributeSetS);
        // get index i of omega in solving vector
        Function<Map.Entry<Integer, Zp.ZpElement>, BigInteger> i = omega -> BigInteger.valueOf(omega.getKey());
        // get value w_i of omega in solving vector
        Function<Map.Entry<Integer, Zp.ZpElement>, Zp.ZpElement> w = Map.Entry::getValue;
        // get receiver of share i
        Function<Map.Entry<Integer, Zp.ZpElement>, Attribute> rho = omega ->
                (Attribute) msp.getShareReceiver(omega.getKey());

        // supplies stream with all entries of the solving vector having a non-zero value w_i, doesn't effect the
        // products
        Supplier<Stream<Map.Entry<Integer, Zp.ZpElement>>> nonZeroOmegas = () ->
                solvingVector.entrySet().parallelStream()
                        .filter(omega -> !w.apply(omega).equals(zp.getZeroElement()));

        // product of E_i^(-w_i)
        GroupElement eiProd = nonZeroOmegas.get()
                .map(omega -> c.getE().get(i.apply(omega)).pow(w.apply(omega)).inv())
                .reduce(pp.getGroupG1().getNeutralElement(), GroupElement::op);

        // product of d(rho_i)^(-w_i)
        GroupElement dRhoiProd = nonZeroOmegas.get()
                .map(omega -> d.get(rho.apply(omega)).pow(w.apply(omega)).inv())
                .reduce(pp.getGroupG1().getNeutralElement(), GroupElement::op);

        GroupElement map1 = pp.getE().apply(eiProd, dTwoPrime);
        GroupElement map2 = pp.getE().apply(c.getETwoPrime(), dRhoiProd.op(dPrime));
        return map1.op(map2).compute();
    }

    /**
     * Checks if the number of shared attributes (the lines in the MSP) are valid and if the MSP is injective (all lines
     * are different attributes).
     *
     * @param shares maps share indices to the shares
     * @param msp the msp to check
     * @param lMax the maximum number of shares allowed
     * @return true if MSP is valid, else false
     */
    protected boolean isMonotoneSpanProgramValid(Map<Integer, Zp.ZpElement> shares, MonotoneSpanProgram msp, int lMax) {
        // check for line count
        if (shares.size() > lMax) {
            return false;
        } else {
            Set<Attribute> attributes = new HashSet<>();
            for (Map.Entry<Integer, Zp.ZpElement> share : shares.entrySet()) {
                if (attributes.contains((Attribute) msp.getShareReceiver(share.getKey()))) {
                    return false;
                } else {
                    attributes.add((Attribute) msp.getShareReceiver(share.getKey()));
                }
            }
            return true;
        }
    }

    public ABECPWat11PublicParameters getPublicParameters() {
        return pp;
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interface are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */
    public MasterSecret getMasterSecret(Representation repr) {
        return new ABECPWat11MasterSecret(pp.getGroupG1(), repr);
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interface are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */

    /**
     * Generates a decryption key that will be able to decrypt ciphertexts where getPredicate().check(kind, cind) = 1.
     *
     * @param msk  the master secret obtained during setup.
     * @param kind the key index specifying which ciphertexts are readable.
     * @return a key used for decrypt().
     * <p>
     * Creates a decryption key out of a given {@link SetOfAttributes}. This decryption key can only decrypt
     * cipher texts that are encrypted with policies that are satisfied by this set of attributes.
     */
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof ABECPWat11MasterSecret))
            throw new IllegalArgumentException("Not a valid MasterSecret for this scheme");
        if (!(kind instanceof SetOfAttributes))
            throw new IllegalArgumentException("SetOfAttributes expected as KeyIndex");

        SetOfAttributes attributes = (SetOfAttributes) kind;

        if (attributes.size() > pp.getN())
            throw new IllegalArgumentException(
                    "number of attributes cannot be greater than " + pp.getN() + ", but is " + attributes.size());

        GroupElement gy = ((ABECPWat11MasterSecret) msk).get();

        Zp.ZpElement u = zp.getUniformlyRandomUnit();
        GroupElement dPrime = gy.op(pp.getgA().pow(u)).compute();
        GroupElement dPrime2 = pp.getG().pow(u).compute();

        Map<Attribute, GroupElement> d = new HashMap<>();

        for (Attribute x : attributes) {
            // If hash function is WatersHash, then x_element corresponds to a h_i as
            // defined in the paper.
            GroupElement xElement = pp.getHashToG1().hash(x);
            GroupElement dx = xElement.pow(u).compute();
            d.put(x, dx);
        }

        return new ABECPWat11DecryptionKey(d, dPrime, dPrime2);
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interface are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */

    /**
     * Generates an encryption key such that ciphertexts created using that key are decryptable using keys where
     * getPredicate().check(kind, cind) = 1.
     *
     * @param cind the ciphertext index specifying who should be able to read the ciphertext.
     * @return a key used for encrypt().
     * <p>
     * Generates an encryption key out of a given {@link Policy}. This means that all plain texts that are
     * encrypted with this encryption key can only be decrypted if the set of attributes of the respective
     * decryption key satisfy this policy.
     */
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof Policy))
            throw new IllegalArgumentException("Expected Policy as CipherTextIndex");
        Policy policy = (Policy) cind;
        return new ABECPWat11EncryptionKey(policy);
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */

    /**
     * This scheme uses a {@link Policy} as the CipherTextIndex and a {@link SetOfAttributes} as the KeyIndex.
     */
    public Predicate getPredicate() {
        return (kind, cind) -> {
            if (!(cind instanceof Policy))
                throw new IllegalArgumentException("Expected Policy as CiphertextIndex");
            if (!(kind instanceof SetOfAttributes))
                throw new IllegalArgumentException("Expected SetOfAttributes as KeyIndex ");
            Policy policy = (Policy) cind;
            SetOfAttributes soa = (SetOfAttributes) kind;
            return policy.isFulfilled(soa);
        };
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        AbstractABECPWat11 other = (AbstractABECPWat11) o;
        return Objects.equals(pp, other.pp);
    }
}
