package org.cryptimeleon.craco.sig.ecdsa;

import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.math.serialization.ByteArrayRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;

import java.util.Arrays;

/**
 * Class for a signature of the {@link ECDSASignatureScheme}.
 */
public class ECDSASignature implements Signature, StandaloneRepresentable {

    final byte[] bytes;

    public ECDSASignature(byte[] signatureBytes) {
        this.bytes = signatureBytes;
    }

    public ECDSASignature(Representation repr) {
        this.bytes = ((ByteArrayRepresentation) repr).get();
    }


    @Override
    public Representation getRepresentation() {
        return new ByteArrayRepresentation(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECDSASignature that = (ECDSASignature) o;
        return Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
