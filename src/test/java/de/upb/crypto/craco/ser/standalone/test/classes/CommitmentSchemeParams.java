package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.structures.rings.zn.Zn;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class CommitmentSchemeParams {
    private static final int NUMBER_OF_MESSAGES = 3;
    private static final Zn zn = new Zn(BigInteger.valueOf(2).pow(260));

    public static Collection<StandaloneTestParams> get() {

        PedersenCommitmentScheme scheme =
                new PedersenCommitmentScheme(zn.asAdditiveGroup(), NUMBER_OF_MESSAGES);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        toReturn.add(new StandaloneTestParams(PedersenCommitmentScheme.class, scheme));
        toReturn.add(new StandaloneTestParams(HashThenCommitCommitmentScheme.class, new HashThenCommitCommitmentScheme(scheme, new SHA256HashFunction())));
        return toReturn;
    }
}
