package de.upb.crypto.craco.kdf.uextr;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.kem.KeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyMaterial;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.polynomial.Seed;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class UnpredictabilityKeyDerivationFunction implements KeyDerivationFunction<ByteArrayImplementation> {

    private static final Logger logger = LogManager.getLogger(UnpredictabilityKeyDerivationFamily.class.getName());

    @Represented
    private UnpredictabilityKeyDerivationFamily unpredictabilityKeyDerivationFamily;
    // maps index-> function
    @Represented(restorer = "int -> foo")
    private Map<Integer, KWiseDeltaDependentHashFunction> functions;

    public UnpredictabilityKeyDerivationFunction(
            UnpredictabilityKeyDerivationFamily unpredictabilityKeyDerivationFamily, Seed seed) {
        this.unpredictabilityKeyDerivationFamily = unpredictabilityKeyDerivationFamily;
        logger.debug("Using the provided seed to seed the HashFamilies");
        if (seed.getBitLength() != unpredictabilityKeyDerivationFamily.seedLength()) {
            throw new IllegalArgumentException("Invalid Seed Length");
        }
        functions = new HashMap<>();
        int startIndex = 0;
        for (KWiseDeltaDependentHashFamily family : unpredictabilityKeyDerivationFamily.getFamilyList()) {
            logger.debug("Using " + family.seedLength() + " bits to seed family " + family);
            functions.put(unpredictabilityKeyDerivationFamily.getFamilyList().indexOf(family),
                    family.seedFunction(new Seed(seed.getInternalSeed(), startIndex, family.seedLength())));
            startIndex = startIndex + family.seedLength();
        }
    }

    public UnpredictabilityKeyDerivationFunction(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public ByteArrayImplementation deriveKey(KeyMaterial material) {
        if (material.getMinEntropyInBit() < unpredictabilityKeyDerivationFamily.minEntropy()) {
            throw new IllegalArgumentException("The material has too little minEntropy for this KDF");
        }
        ByteArrayAccumulator accu = new ByteArrayAccumulator();
        material.updateAccumulator(accu);
        byte[] bytes = accu.extractBytes();
        if (bytes.length != unpredictabilityKeyDerivationFamily.getInputLength() / 8) {
            throw new IllegalArgumentException(
                    "The key material does not match the inputLength (required length is " + unpredictabilityKeyDerivationFamily
                            .getInputLength()
                            + " bits, given is " + bytes.length * 8 + " bits)");
        }
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (HashFunction func : functions.values()) {
            try {
                stream.write(func.hash(bytes));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return new ByteArrayImplementation(stream.toByteArray());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + getOuterType().hashCode();
        result = prime * result + ((functions == null) ? 0 : functions.hashCode());
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
        UnpredictabilityKeyDerivationFunction other = (UnpredictabilityKeyDerivationFunction) obj;
        if (!getOuterType().equals(other.getOuterType()))
            return false;
        if (functions == null) {
            if (other.functions != null)
                return false;
        } else if (!functions.equals(other.functions))
            return false;
        return true;
    }

    private UnpredictabilityKeyDerivationFamily getOuterType() {
        return unpredictabilityKeyDerivationFamily;
    }

}
