package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * An SignatureScheme has the ability to sign plaintexts
 * and verify the resulting signature (using SigningKeys and VerificationKeys).
 * <p>
 * The functional contract is that verify(sign(m, sk), pk) = 1 for sk, pk that
 * "fit" together (depending on the concrete type of signature scheme).
 * <p>
 * Sub-Interfaces define how you obtain signing and verification keys.
 * <p>
 * SignatureScheme are stand-alone representable. So once set up,
 * you can restore the same scheme with the same public parameters
 * using the Representation mechanism (i.e. call the class's constructor
 * with a Representation argument).
 * <p>
 * We note that we see all signature schemes as single-message schemes.
 * However, some signature schemes may be able to sign {@link de.upb.crypto.craco.common.MessageBlock}s
 * (cf., for example, {@link StandardMultiMessageSignatureScheme}).
 *
 * @author feidens
 */
public interface SignatureScheme extends StandaloneRepresentable {
    /**
     * Signing algrithm of the signature scheme. The secret key should contain all information
     * necessary to sign, therefore public key is not needed.
     *
     * @param plainText
     * @param secretKey
     * @return signature on plainText under secretKey
     */
    Signature sign(PlainText plainText, SigningKey secretKey);

    Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey);


    PlainText getPlainText(Representation repr);

    Signature getSignature(Representation repr);

    SigningKey getSigningKey(Representation repr);

    VerificationKey getVerificationKey(Representation repr);

    default Signature sign(Representation plainText, Representation secretKey) {
        return sign(getPlainText(plainText), getSigningKey(secretKey));
    }

    default Boolean verify(Representation plainText, Representation signature, Representation publicKey) {
        return verify(getPlainText(plainText), getSignature(signature), getVerificationKey(publicKey));
    }

    /**
     * Provides an injective mapping of the byte[] to a {@link PlainText} usable with this scheme (which may be a
     * MessageBlock).
     * It only guarantees injectivity for arrays of the same length. Applications that would like to use mapToPlaintext
     * with multiple different array lengths, may want to devise a padding method and then only call mapToPlaintext with
     * byte[] of the same (padded) length.
     * This method may throw an {@link IllegalArgumentException} if there is no injective {@link PlainText} element of
     * these bytes (e.g., the byte array is too long).
     * <p>
     * The contract is that VerificationKey pk and SigningKey sk are compatible (in the sense that verify(m,sign(m,
     * sk),pk) == true),
     * then mapToPlaintext(bytes, pk) equals mapToPlaintext(bytes, sk) for all bytes.
     *
     * @param bytes bytes to be mapped to a {@link PlainText}
     * @param pk    the verification key for which the resulting PlainText should be valid
     *              (note that the plaintext space may differ for different verification keys).
     * @return the corresponding plaintext
     */
    PlainText mapToPlaintext(byte[] bytes, VerificationKey pk);

    /**
     * Provides an injective mapping of the byte[] to a {@link PlainText} usable with this scheme (which may be a
     * MessageBlock).
     * It only guarantees injectivity for arrays of the same length. Applications that would like to use mapToPlaintext
     * with multiple different array lengths, may want to devise a padding method and then only call mapToPlaintext with
     * byte[] of the same (padded) length.
     * This method may throw an {@link IllegalArgumentException} if there is no injective {@link PlainText} element of
     * these bytes (e.g., the byte array is too long).
     * <p>
     * The contract is that VerificationKey pk and SigningKey sk are compatible (in the sense that verify(m,sign(sk,
     * m),pk) == true),
     * then mapToPlaintext(bytes, pk) equals mapToPlaintext(bytes, sk) for all bytes.
     *
     * @param bytes bytes to be mapped to a {@link PlainText}
     * @param sk    the signing key for which the resulting PlainText should be valid
     *              (note that the plaintext space may differ for different signing keys).
     * @return the corresponding plaintext
     */
    PlainText mapToPlaintext(byte[] bytes, SigningKey sk);

    /**
     * As described in {@link #mapToPlaintext} there might be no injective {@link PlainText} for some byte arrays, e.g.
     * if the byte array is too long. Therefore, this method provides the maximal number of bytes that can be mapped
     * injectively to a {@link PlainText}.
     *
     * @return maximal number of bytes that can be given to {@link #mapToPlaintext}.
     */
    int getMaxNumberOfBytesForMapToPlaintext();
}
