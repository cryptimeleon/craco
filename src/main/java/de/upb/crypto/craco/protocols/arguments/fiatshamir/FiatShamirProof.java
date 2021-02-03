package de.upb.crypto.craco.protocols.arguments.fiatshamir;

import de.upb.crypto.math.serialization.ByteArrayRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.cartesian.Vector;

import java.util.Arrays;

public class FiatShamirProof implements Representable {
    public final Representation compressedTranscript;
    public final byte[] additionalData;

    public FiatShamirProof(Representation compressedTranscript, byte[] additionalData) {
        this.compressedTranscript = compressedTranscript;
        this.additionalData = Arrays.copyOf(additionalData, additionalData.length);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("transcript", compressedTranscript);
        repr.put("additionalData", new ByteArrayRepresentation(additionalData));
        return repr;
    }
}
