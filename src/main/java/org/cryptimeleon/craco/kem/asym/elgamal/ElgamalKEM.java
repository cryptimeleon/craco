package org.cryptimeleon.craco.kem.asym.elgamal;

import org.cryptimeleon.craco.enc.*;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalCipherText;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalEncryption;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalPlainText;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalPrivateKey;
import org.cryptimeleon.craco.enc.sym.streaming.aes.ByteArrayImplementation;
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
 * Group G of size q, generator g, public key h=g^a, secret key a
 * <p>
 * Encrypt Message R:
 * <p>
 * 1. select s UAR in Z_q 2. C=<R g^(as),g^s>
 * <p>
 * Decrypt C:
 * <p>
 * 1. Parse C as C=<C1,C2> 2. Compute C1*C2^(-a)
 * <p>
 * <p>
 * FOT Elgamal with KEM and H1:Gx{0,1}^n->Z_q, H2:G->{0,1}^n,
 * <p>
 * Encaps k:
 * <p>
 * 1. select R UAR in G and k UAR in {0,1}^n, compute s=H(R,k) (commitment on
 * R,k) 2. Elgamal Encrypt R with random tape s to obtain C=<C1,C2> 3. OTP
 * encrypt k with r=H2(R): C2= r xor k
 * <p>
 * Decaps k: 1. Parse C=<C1,C2,C3> 2. Elgamal Decrypt <C1,C2> to obtain R' 3.
 * OTP Decrypt C3 with H2(R) to obtain k' 4. recover commitment s'=H1(R',k') 5.
 * check commitment by ElGamal encryption R' with s' and comparison with C1 a.
 * if ok, return k' b. otherwithe return fail
 * <p>
 * <p>
 * This implementation uses org.cryptimeleon.craco.enc.asym.elgamal for Elgamal
 * Encryption
 *
 *
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
        ElgamalPlainText M = new ElgamalPlainText(R);

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
        ElgamalPlainText M = (ElgamalPlainText) encryptionScheme.decrypt(C.getElgamalCipherText(), sk);

        GroupElement R = M.getPlaintext();

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
    public KeyPair generateKeyPair() {
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
