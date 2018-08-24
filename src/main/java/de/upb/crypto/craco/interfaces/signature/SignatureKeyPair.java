package de.upb.crypto.craco.interfaces.signature;

/**
 * A container for a pair of VerificationKey and SigningKey.
 */
public class SignatureKeyPair<VerificationKeyType extends VerificationKey, SigningKeyType extends SigningKey> {

    private VerificationKeyType pk;
    private SigningKeyType sk;

    public SignatureKeyPair(VerificationKeyType pk, SigningKeyType sk) {
        super();
        this.pk = pk;
        this.sk = sk;
    }

    public VerificationKeyType getVerificationKey() {
        return pk;
    }

    public SigningKeyType getSigningKey() {
        return sk;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pk == null) ? 0 : pk.hashCode());
        result = prime * result + ((sk == null) ? 0 : sk.hashCode());
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
        SignatureKeyPair other = (SignatureKeyPair) obj;
        if (pk == null) {
            if (other.pk != null)
                return false;
        } else if (!pk.equals(other.pk))
            return false;
        if (sk == null) {
            if (other.sk != null)
                return false;
        } else if (!sk.equals(other.sk))
            return false;
        return true;
    }

}
