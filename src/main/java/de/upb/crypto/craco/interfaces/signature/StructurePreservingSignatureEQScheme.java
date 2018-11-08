package de.upb.crypto.craco.interfaces.signature;


import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.structures.zn.Zn;

/**
 * A structure-preserving signature scheme on equivalence classes
 * <p>
 * This is a special case of a multi-message signature scheme
 * because SPS-EQ additionally supports a change of the representative of the equivalence class that is signed.
 * <p>
 */
public interface StructurePreservingSignatureEQScheme extends StandardMultiMessageSignatureScheme {

    Signature chgRep(PlainText plainText, Signature sigma, Zn.ZnElement mu, VerificationKey publicKey);
}
