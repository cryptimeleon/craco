package de.upb.crypto.craco.sig.interfaces;


import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.sig.interfaces.Signature;
import de.upb.crypto.craco.sig.interfaces.StandardMultiMessageSignatureScheme;
import de.upb.crypto.craco.sig.interfaces.VerificationKey;
import de.upb.crypto.math.structures.zn.Zn;

/**
 * A structure-preserving signature scheme on equivalence classes
 * <p>
 * This is a special case of a multi-message signature scheme
 * because SPS-EQ additionally supports a change of the representative of the equivalence class that is signed.
 * <p>
 */
public interface StructurePreservingSignatureEQScheme extends StandardMultiMessageSignatureScheme {

    /**
     * Shortcut version of {@link #chgRepWithVerify(PlainText, Signature, Zn.ZnElement, VerificationKey)} if you already
     * externally verified the signature on the plaintext under the given verification/public key use this method.
     * Otherwise use {@link #chgRepWithVerify(PlainText, Signature, Zn.ZnElement, VerificationKey)}.
     * The change representative method returns a signature matching the new representative of [M]_R.
     * The new representative of [M]_R is supposed to be generated externally by using the plain text (M) and
     * element mu. The matching signature sigma' for the new representative mu*M of [M]_R is computed such that
     * Verify(M^{mu},sigma') = 1.
     * See paper [1] for details.
     *
     * @param signature
     * @param mu
     * @param publicKey
     * @return null of the signature given is not valid on plainText under publicKey, else it returns a valid signature
     * on mu*plainText
     */
    Signature chgRep(Signature signature, Zn.ZnElement mu, VerificationKey publicKey);

    /**
     * Same as {@link #chgRep(Signature, Zn.ZnElement, VerificationKey)} with one addition.
     * The given siganture is verifed on the plaintext under the public key.
     *
     * @param signature
     * @param mu
     * @param publicKey
     * @return null if the signature given is not valid on plainText under publicKey, else a valid signature
     * on mu*plainText
     */
    Signature chgRepWithVerify(PlainText plainText, Signature signature, Zn.ZnElement mu, VerificationKey publicKey);

    /**
     * Changes representative of the message equivalence class [M]_R given message plainText and value mu to compute the
     * new representative.
     * Corresponds to {@link #chgRepWithVerify(PlainText, Signature, Zn.ZnElement, VerificationKey)}, but handles the
     * change of representative of the message equivalence class [M]_R.
     *
     *
     * @param plainText
     * @param mu
     * @return
     */
    PlainText chgRepMessage(PlainText plainText, Zn.ZnElement mu);
}
