package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;
import java.util.Objects;

public class PedersenOpenValue implements OpenValue {

    @Represented
    private Zp zp;

    @UniqueByteRepresented
    @RepresentedArray(elementRestorer = @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD))
    private Zp.ZpElement[] messages;

    @UniqueByteRepresented
    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement randomness;

    public PedersenOpenValue(Zp.ZpElement[] messages, Zp.ZpElement randomness) {
        this.messages = messages;
        this.randomness = randomness;
        this.zp = randomness.getStructure();
    }

    public PedersenOpenValue(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);

    }

    public Zp.ZpElement[] getMessages() {
        return messages;
    }

    public Zp.ZpElement getRandomValue() {
        return randomness;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        for (Zp.ZpElement message : messages) {
            byteAccumulator.escapeAndSeparate(message);
        }
        byteAccumulator.append(randomness);
        return byteAccumulator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PedersenOpenValue that = (PedersenOpenValue) o;
        return Objects.equals(zp, that.zp) &&
                Arrays.equals(messages, that.messages) &&
                Objects.equals(randomness, that.randomness);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(zp, randomness);
        result = 31 * result + Arrays.hashCode(messages);
        return result;
    }
}
