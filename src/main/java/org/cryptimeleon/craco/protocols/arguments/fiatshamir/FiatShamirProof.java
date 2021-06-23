package org.cryptimeleon.craco.protocols.arguments.fiatshamir;

import org.cryptimeleon.craco.protocols.arguments.sigma.Challenge;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

import java.util.Objects;

public class FiatShamirProof implements Representable {
    public final Representation compressedTranscript;
    public final Challenge challenge;

    public FiatShamirProof(Representation compressedTranscript, Challenge challenge) {
        this.compressedTranscript = compressedTranscript;
        this.challenge = challenge;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("transcript", compressedTranscript);
        repr.put("challenge", challenge.getRepresentation());
        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiatShamirProof that = (FiatShamirProof) o;
        return Objects.equals(compressedTranscript, that.compressedTranscript) && Objects.equals(challenge, that.challenge);
    }

    @Override
    public int hashCode() {
        return Objects.hash(compressedTranscript, challenge);
    }
}
