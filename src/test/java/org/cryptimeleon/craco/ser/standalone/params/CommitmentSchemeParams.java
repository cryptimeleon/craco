package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.structures.rings.zn.Zn;

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
