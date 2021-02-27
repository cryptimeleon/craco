package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;

public class CommitmentStandaloneReprTests extends StandaloneReprSubTest {
    private final int NUMBER_OF_MESSAGES = 3;
    private final Zn zn = new Zn(BigInteger.valueOf(2).pow(260));
    private final PedersenCommitmentScheme pedersen = new PedersenCommitmentScheme(zn.asAdditiveGroup(), NUMBER_OF_MESSAGES);

    public void testPedersen() {
        test(pedersen);
    }

    public void testHashThenCommit() {
        test(new HashThenCommitCommitmentScheme(pedersen, new SHA256HashFunction()));
    }
}
