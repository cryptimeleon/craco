package de.upb.crypto.craco.protocols.arguments.fiatshamir;

import de.upb.crypto.craco.protocols.arguments.sigma.Challenge;
import de.upb.crypto.math.serialization.ByteArrayRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.cartesian.Vector;

import java.util.Arrays;

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
