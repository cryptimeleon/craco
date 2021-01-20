package de.upb.crypto.craco.protocols.arguments.fiatshamir;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

public class FiatShamirProof implements Representable {
    public final Representation compressedTranscript;

    public FiatShamirProof(Representation compressedTranscript) {
        this.compressedTranscript = compressedTranscript;
    }

    @Override
    public Representation getRepresentation() {
        return compressedTranscript;
    }
}
