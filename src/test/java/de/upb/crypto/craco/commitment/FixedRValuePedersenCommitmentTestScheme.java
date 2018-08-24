package de.upb.crypto.craco.commitment;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class FixedRValuePedersenCommitmentTestScheme extends PedersenCommitmentScheme {
    public FixedRValuePedersenCommitmentTestScheme(PedersenPublicParameters pp) {
        super(pp);
    }

    public FixedRValuePedersenCommitmentTestScheme(Representation representation) {
        super(representation);
    }

    // Committing Message using r = zpTwo
    @Override
    protected Zp.ZpElement generateR(BigInteger p) {
        Zp zp = new Zp(p);
        return zp.getOneElement().add(zp.getOneElement());
    }
}
