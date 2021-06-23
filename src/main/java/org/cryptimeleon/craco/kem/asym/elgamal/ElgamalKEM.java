package org.cryptimeleon.craco.kem.asym.elgamal;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.enc.*;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalCipherText;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalEncryption;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalPrivateKey;
import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.kem.asym.AsymmetricKEM;
import org.cryptimeleon.math.hash.HashFunction;
import org.cryptimeleon.math.hash.impl.ByteArrayAccumulator;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.math.BigInteger;
import java.util.Objects;

/**
 * This class implements the Fujisaki Okamoto transformation (FOT) of an ElGamal
 * KEM.
 * <p>
 * The FOT is a transformation to transform a CPA secure public key encryption
 * scheme into a CCA secure encryption scheme in the RO model.
 * <p>
 * The main idea of FOT is to replace the randomness of ElGamal encryption with
 * a commitment on a random Message. Then, after decaps/decrypt we can check the
 * commitment by re-encrypt the decrypted message with the same commitment as
 * randomness.
 * <p>
 * ElGamal:
 * <p>
 * Group \(\mathbb{G}\) of size \(q\), generator \(g\), public key \(h=g^a\), secret key \(a\)
 * <p>
 * Encrypt message \(R\):
 * <ol>
 * <li> Select \(s\) uniformly at random from \(\mathbb{Z}_q\)
 * <li> Output ciphertext \(C=(R g^{as},g^s)\)
 * </ol>
 * <p>
 * Decrypt \(C\):
 * <ol>
 *  <li> Parse C as \(C=(C_1,C_2)\)
 *  <li> Compute \(C_1 \cdot C_2^(-a)\)
 * </ol>
 * <p>
 * FOT Elgamal with KEM and \(H_1 : \mathbb{G} \times \{0,1\}^n \rightarrow \mathbb{Z}_q,
 * H_2 : \mathbb{G} \rightarrow \{0,1\}^n\),
 * <p>
 * Encaps \(k\):
 * <ol>
 *  <li> Select \(R\) uniformly at random from \(\mathbb{G}\) and \(k\) uniformly at random in \(\{0,1\}^n\),
 *  and compute \(s=H(R,k)\) (commitment on \(R,k\))
 *  <li> Elgamal encrypt \(R\) with random tape \(s\) to obtain \((C_1,C_2)\)
 *  <li> One-time-pad encrypt \(k\) with \(r=H_2(R)\): \(C_3= r \oplus k\)
 *  <li> Output \(C = (C_1, C_2, C_3)\)
 * </ol>
 * <p>
 * Decaps \(k\):
 * <ol>
 *  <li> Parse \(C=(C_1,C_2,C_3)\)
 *  <li> Elgamal decrypt \((C_1,C_2)\) to obtain message \(R'\)
 *  <li> One-time-pad decrypt \(C_3\) with \(H_2(R)\) to obtain \(k'\)
 *  <li> Recover commitment \(s'=H_1(R',k')\)
 *  <li> Check commitment by ElGamal encrypting \(R'\) with \(s'\) and comparing it with \(C_1 \cdot a\).
 *       If ok, return \(k' \cdot b\). Otherwise return fail
 * </ol>
 * @see ElgamalEncryption
 */


public class ElgamalKEM implements AsymmetricKEM<SymmetricKey> {

    public class KeyAndCiphertextAndNonce {
        public KeyAndCiphertext<SymmetricKey> keyAndCiphertext;
        public BigInteger nonce;

        public KeyAndCiphertextAndNonce(KeyAndCiphertext<SymmetricKey> keyAndCiphertext, BigInteger nonce) {

            this.keyAndCiphertext = keyAndCiphertext;
            this.nonce = nonce;
        }
    }

    /**
     * The underlying ElGamal encryption scheme
     */
    @Represented
    private ElgamalEncryption encryptionScheme;

    /**
     * Hash function to construct H1 and H2
     */
    @Represented
    private HashFunction messageDigest;

    /**
     * Setup Elgamal KEM for given group and message digest.
     * <p>
     * Here, md is used to construct hash functions H1 and H2.
     *
     * @param group - group where scheme is defined
     * @param md    - message digest to construct hash functions
     */
    public ElgamalKEM(Group group, HashFunction md) {

        this.encryptionScheme = new ElgamalEncryption(group);
        // this.kdf = new HashBasedKeyDerivationFunction(md);
        this.messageDigest = md;
    }

    public ElgamalKEM(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((encryptionScheme == null) ? 0 : encryptionScheme.hashCode());
        result = prime * result + ((messageDigest == null) ? 0 : messageDigest.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ElgamalKEM other = (ElgamalKEM) obj;
        return Objects.equals(encryptionScheme, other.encryptionScheme)
                && Objects.equals(messageDigest, other.messageDigest);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public KeyAndCiphertext<SymmetricKey> encaps(EncryptionKey pk) {
        KeyAndCiphertextAndNonce kcn = this.encaps_internal(pk);
        return kcn.keyAndCiphertext;
    }

    /**
     * Generates a random symmetric key, encapsulates it, and returns it together with the nonce used and ciphertext.
     *
     * @param pk the public key to use for encapsulation
     * @return the resulting key, ciphertext, and nonce
     */
    public KeyAndCiphertextAndNonce encaps_internal(EncryptionKey pk) {
        HashFunction md = messageDigest;

        byte[] random = RandomGenerator.getRandomBytes(md.getOutputLength());

        /*
         * pick random message R and encode as plaintext
         */
        GroupElement R = this.encryptionScheme.getGroup().getUniformlyRandomElement();
        GroupElementPlainText M = new GroupElementPlainText(R);

        /*
         *
         * compute H2(R)
         */
        ByteArrayImplementation r = new ByteArrayImplementation(md.hash(R));

        /* convert random tape to symmetric key k */
        ByteArrayImplementation k = new ByteArrayImplementation(random);

        /*
         * compute s=H(R,k)
         */
        byte[] h = computeNonceHash(md, R, k);
        BigInteger s = new BigInteger(h);

        /*
         * encrypt R, resp. M, with nonce s under public key pk
         */
        ElgamalCipherText c = (ElgamalCipherText) this.encryptionScheme.encrypt(M, pk, s);

        /*
         * now blind k with H(R)
         */
        ByteArrayImplementation encaps = k.xor(r);

        /*
         * wrap into ciphertext structure
         */
        ElgamalKEMCiphertext C = new ElgamalKEMCiphertext(c, encaps);

        KeyAndCiphertext<SymmetricKey> result = new KeyAndCiphertext<SymmetricKey>();
        result.encapsulatedKey = C;
        result.key = k;

        return new KeyAndCiphertextAndNonce(result, s);
    }

    private byte[] computeNonceHash(HashFunction md, GroupElement r, ByteArrayImplementation k) {
        ByteArrayAccumulator acu = new ByteArrayAccumulator();
        acu.append(r);
        acu.append(k);
        byte[] hash = md.hash(acu.extractBytes());

        /*make sure that we get positive integer by injective mapping
         * to avoid exponentiation with negative integers or conversion problems
         * therefore, we prepend with 0 byte because BigInteger interprets this as positive.
         * */
        ByteArrayAccumulator hAccu = new ByteArrayAccumulator();
        hAccu.append(new byte[]{0});
        hAccu.append(hash);
        return hAccu.extractBytes();
    }

    @Override
    public ByteArrayImplementation decaps(CipherText encapsulatedKey, DecryptionKey sk) {
        HashFunction md = messageDigest;

        ElgamalKEMCiphertext C = (ElgamalKEMCiphertext) encapsulatedKey;

        /*
         * do elgamal decryption to recover R (embedded into M)
         */
        GroupElementPlainText M = (GroupElementPlainText) encryptionScheme.decrypt(C.getElgamalCipherText(), sk);

        GroupElement R = M.get();

        /*
         * recover r=H(R)
         */
        ByteArrayImplementation r = new ByteArrayImplementation(md.hash(R));

        /*
         * recover k= C3 xor r
         */
        ByteArrayImplementation k = C.getSymmetricEncryption().xor(r);

        /*
         * recover s=H(R,k)
         */
        byte[] h = computeNonceHash(md, R, k);
        BigInteger s = new BigInteger(h);

        /*
         * encrypt R with given random tape s
         */
        ElgamalCipherText c_prime = (ElgamalCipherText) encryptionScheme.encrypt(M,
                ((ElgamalPrivateKey) sk).getPublicKey(), s);

        /*
         * check commitment on R and k by comparing resulting ciphertexts.
         * Return fail (null) in case check fails.
         */

        //return k;
        if (c_prime.getC2().equals(C.getElgamalCipherText().getC2())) {
            return k;
        } else {
            return new ByteArrayImplementation(new byte[0]);
        }
    }

    @Override
    public EncryptionKeyPair generateKeyPair() {
        return encryptionScheme.generateKeyPair();
    }

    public ByteArrayImplementation getKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public ElgamalKEMCiphertext restoreEncapsulatedKey(Representation repr) {
        return new ElgamalKEMCiphertext(repr, encryptionScheme);
    }

    @Override
    public EncryptionKey restoreEncapsulationKey(Representation repr) {
        return this.encryptionScheme.restoreEncryptionKey(repr);
    }

    @Override
    public ElgamalPrivateKey restoreDecapsulationKey(Representation repr) {
        return this.encryptionScheme.restoreDecryptionKey(repr);
    }

    public ElgamalEncryption getEncryptionScheme() {
        return encryptionScheme;
    }

    public void setEncryptionScheme(ElgamalEncryption encryptionScheme) {
        this.encryptionScheme = encryptionScheme;
    }

    public HashFunction getHashFunction() {
        return messageDigest;
    }

    public void setHashFunction(HashFunction messageDigest) {
        this.messageDigest = messageDigest;
    }

}
