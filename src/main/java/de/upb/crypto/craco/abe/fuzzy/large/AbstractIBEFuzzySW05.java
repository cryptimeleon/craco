package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.pe.*;
import de.upb.crypto.craco.common.utils.LagrangeUtil;
import de.upb.crypto.craco.kem.fuzzy.large.IBEFuzzySW05KEM;
import de.upb.crypto.craco.kem.fuzzy.large.IBEFuzzySW05KEMCipherText;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.rings.polynomial.PolynomialRing;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Combines shared functionality of {@link IBEFuzzySW05} and {@link IBEFuzzySW05KEM}.
 *
 * @author Denis Diemert (based on {@link IBEFuzzySW05})
 */
public class AbstractIBEFuzzySW05 {
    /**
     * The public parameters for this scheme.
     */
    protected IBEFuzzySW05PublicParameters pp;
    /**
     * Zp_{sizeof(groupG1)}
     */
    protected Zp zp;

    /**
     * Checks if an identity is valid
     *
     * @param id identity
     * @return true if identity consists of exactly n attributes from Z_p, false otherwise
     */
    public boolean isIdentityValid(Identity id) {
        if (id.getAttributes().size() != pp.getN().intValue()) {
            return false;
        }
        for (BigIntegerAttribute attr : id.getAttributes()) {
            if (attr.getAttribute().compareTo(pp.getGroupG1().size()) >= 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Creates a subset of specific size
     *
     * @param s     set
     * @param count size of subset
     * @return subset of size count
     */
    protected Set<BigIntegerAttribute> subset(Set<BigIntegerAttribute> s, int count) {
        Set<BigIntegerAttribute> result = new HashSet<>();
        int i = 0;
        for (BigIntegerAttribute bi : s) {
            result.add(bi);
            i++;
            if (i == count) {
                break;
            }
        }
        return result;
    }

    /**
     * Computes {@link IBEFuzzySW05KEMCipherText#getEElementMap()} in the fuzzy IBE encaps and encrypt.
     *
     * @param omega identity
     * @param s     secret value
     * @return {E_i = T(i)^s}_{i \in \omega}
     */
    protected Map<BigInteger, GroupElement> computeE(Identity omega, Zp.ZpElement s) {
        return omega.getAttributes().parallelStream()
                .map(BigIntegerAttribute::getAttribute)
                .collect(Collectors.toConcurrentMap(
                        // key: attribute i
                        i -> i,
                        // value: i -> T(i)^s
                        i -> {
                            GroupElement hashedi = pp.getHashToG1().hash((i.subtract(BigInteger.ONE)).toString(10));
                            return hashedi.pow(s).compute();
                        }
                ));
    }

    /**
     * Restores Y^{s}, which is the noise factor for the {@link IBEFuzzySW05} encryption. Y^s is needed to
     * decrypt a ciphertext or to decapsulate a key.
     * <p>
     * It computes Y^s in the following way: Given subset S \subseteq (\omega \cap \omega') of attributes with |S| = d,
     * compute the following:
     * <p>
     * 1) Numerator: \prod_{i \in S} e(R_i^{lg}, E_i).
     * 2) Denominator: e(\prod D_i^lg, E'')
     * <p>
     * where lg is the lagrange coefficient of party i, set S for x = 0
     * <p>
     * Then, Y^{s} = (Numerator / Denominator)^{-1}
     *
     * @param ct           ciphertext or encapsulated key for which Y^s shall be restored
     * @param dElementMap  {@link IBEFuzzySW05DecryptionKey#getDElementMap()}
     * @param rElementMap  {@link IBEFuzzySW05DecryptionKey#getRElementMap()}
     * @param attributeSet a subset of the intersection of the ciphertext's and secret key's identity of size d. It
     *                     is assumed
     *                     that the size of the set is correct.
     * @return Y^s as described above
     */
    protected GroupElement restoreYs(IBEFuzzySW05KEMCipherText ct, Map<BigInteger, GroupElement> dElementMap,
                                     Map<BigInteger, GroupElement> rElementMap, Set<BigIntegerAttribute> attributeSet) {
        // get the set of actual attributes values
        HashSet<BigInteger> attributeSetPrime = new HashSet<>();
        attributeSet.forEach(atr -> attributeSetPrime.add(atr.getAttribute()));

        // lagrange coefficient lg(i) = \Delta_{i,S'}(0)
        Function<BigInteger, BigInteger> lg =
                i -> LagrangeUtil.computeCoefficient(i, attributeSetPrime, BigInteger.ZERO, zp);

        // e( R_i^lg, E_i)
        Function<BigInteger, GroupElement> numeratorFactor = i -> pp.getE()
                .apply(
                        rElementMap.get(i).pow(lg.apply(i)),
                        ct.getEElementMap().get(i)
                );
        // \prod_{i \in S} e(R_i^{lg}, E_i)
        GroupElement numerator = attributeSet.parallelStream()
                // get attribute i
                .map(BigIntegerAttribute::getAttribute)
                // compute numerator factor corresponding to i
                .map(numeratorFactor)
                // compute product
                .reduce(pp.getGroupGT().getNeutralElement(), GroupElement::op);

        // D_i^lg
        Function<BigInteger, GroupElement> dFactor = i -> dElementMap.get(i).pow(lg.apply(i));
        // \prod_{i \in S} D_i^lg
        GroupElement dProduct = attributeSet.parallelStream()
                // get attribute i
                .map(BigIntegerAttribute::getAttribute)
                // compute factor corresponding to i
                .map(dFactor)
                // compute product
                .reduce(pp.getGroupG1().getNeutralElement(), GroupElement::op);
        // e( \prod_{i \in S} D_i^lg , E'')
        GroupElement denominator = pp.getE().apply(dProduct, ct.getETwoPrime());

        // compute (numerator / denominator)^{-1} to be consistent with the other KEM's
        return denominator.op(numerator.inv()).compute();
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */
    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */

    /**
     * Generates a decryption key that will be able to
     * decrypt ciphertexts where getPredicate().check(kind, cind) = 1.
     * <p>
     * Generates an {@link DecryptionKey} out of the given {@link Identity}. This {@link DecryptionKey} can only decrypt
     * cipher texts if there are at least {@link IBEFuzzySW05PublicParameters#getIdentityThresholdD()} attributes in the
     * intersection of this
     * {@link Identity} and the {@link Identity} of the respective {@link EncryptionKey}.
     *
     * @param msk  the master secret obtained during setup.
     * @param kind the key index specifying which ciphertexts are readable.
     * @return a key used for decrypt().
     */
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof IBEFuzzySW05MasterSecret))
            throw new IllegalArgumentException("Invalid master secret for this scheme.");
        if (!(kind instanceof Identity))
            throw new IllegalArgumentException("Identity expected as KeyIndex");

        Identity omega = (Identity) kind;
        if (!isIdentityValid(omega))
            throw new IllegalArgumentException("Invalid identity");

        IBEFuzzySW05MasterSecret masterSecret = (IBEFuzzySW05MasterSecret) msk;

        PolynomialRing polyRing = new PolynomialRing(zp);
        // new polynomial q of degree d-1 where q(0) = y
        // assign non zero values to all coefficients
        PolynomialRing.Polynomial q = polyRing.getUniformlyRandomElementWithDegreeAndNoZeros(
                pp.getIdentityThresholdD().intValue() - 1
        );
        q.setCoefficient(0, masterSecret.getY());

        Map<BigInteger, GroupElement> dMap = new HashMap<>();
        Map<BigInteger, GroupElement> rMap = new HashMap<>();

        for (BigIntegerAttribute i : omega.getAttributes()) {
            // r_i <- Zp
            Zp.ZpElement r = zp.getUniformlyRandomUnit();
            // R_i = g^{r_i}
            GroupElement rElement = pp.getG().pow(r);

            // compute T(i-1)
            GroupElement temp = pp.getHashToG1().hash(
                    i.getAttribute().subtract(BigInteger.ONE).toString(10)
            );
            // D_i = g_2^q(i) * T(i-1)^r
            GroupElement dElement = pp.getG2()
                    .pow(q.evaluate(zp.createZnElement(i.getAttribute())))
                    .op(temp.pow(r));

            rMap.put(i.getAttribute(), rElement.compute());
            dMap.put(i.getAttribute(), dElement.compute());
        }
        return new IBEFuzzySW05DecryptionKey(dMap, rMap, omega);
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     *
     */

    /**
     * Generates an {@link EncryptionKey} out of the given {@link Identity}. Plain texts encrypted by this
     * {@link EncryptionKey} can only be decrypted if there are at least
     * {@link IBEFuzzySW05PublicParameters#getIdentityThresholdD()}}
     * attributes in the intersection of this {@link Identity} and the {@link Identity} of the respective
     * {@link DecryptionKey}.
     * <p>
     * Generates an encryption key such that ciphertexts created using
     * that key are decryptable using keys where getPredicate().check(kind, cind) = 1.
     *
     * @param cind the ciphertext index specifying who should be able to read the ciphertext.
     * @return a key used for encrypt().
     */
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof Identity))
            throw new IllegalArgumentException("Identity expected as CiphertextIndex");

        Identity omega = (Identity) cind;

        if (!isIdentityValid(omega))
            throw new IllegalArgumentException("Invalid public key identity");

        return new IBEFuzzySW05EncryptionKey(omega);
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */

    /**
     * This scheme uses a {@link Identity} as {@link KeyIndex} and {@link CiphertextIndex}. The {@link Predicate} is
     * that there are at least {@link IBEFuzzySW05PublicParameters#getIdentityThresholdD()} attributes in the
     * intersection.
     * See {@link PredicateEncryptionScheme} for more information on predicates and their usage.
     */
    public Predicate getPredicate() {
        return (kind, cind) -> {
            if (!(kind instanceof Identity))
                throw new IllegalArgumentException("Identity expected as KeyIndex");
            if (!(cind instanceof Identity))
                throw new IllegalArgumentException("Identity expected as CiphertextIndex");
            Identity iCind = (Identity) cind;
            Identity iKind = (Identity) kind;
            return iCind.intersect(iKind).getAttributes().size() >= pp.getIdentityThresholdD().intValue();
        };
    }

    public IBEFuzzySW05PublicParameters getPublicParameters() {
        return pp;
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new IBEFuzzySW05EncryptionKey(repr);
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new IBEFuzzySW05DecryptionKey(repr, pp);
    }

    /*
     * The interface contracts of the subclasses prescribe implementation of this method. Since the interfaces are
     * different (PredicateEncryptionScheme and PredicateKEM), but share this method, the implementation is extracted
     * here to save duplicate code.
     */
    public MasterSecret getMasterSecret(Representation repr) {
        return new IBEFuzzySW05MasterSecret(repr, pp);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        AbstractIBEFuzzySW05 that = (AbstractIBEFuzzySW05) o;

        if (pp != null ? !pp.equals(that.pp) : that.pp != null)
            return false;
        return zp != null ? zp.equals(that.zp) : that.zp == null;
    }

    @Override
    public int hashCode() {
        return pp != null ? pp.hashCode() : 0;
    }
}
