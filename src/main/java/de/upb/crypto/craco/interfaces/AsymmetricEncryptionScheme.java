package de.upb.crypto.craco.interfaces;


/**
 * A standard public-key encryption scheme where a party
 * generates a pair (pk, sk). Plaintexts are encrypted with pk,
 * the resulting ciphertexts can be decrypted using sk.
 *
 * @author Jan
 */
public interface AsymmetricEncryptionScheme extends EncryptionScheme {

    KeyPair generateKeyPair();

}
