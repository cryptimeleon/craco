package org.cryptimeleon.craco.protocols.arguments.fiatshamir;

import org.cryptimeleon.craco.protocols.arguments.sigma.Challenge;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

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
}
