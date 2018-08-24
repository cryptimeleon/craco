package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.commitment.FixedRValuePedersenCommitmentTestScheme;
import de.upb.crypto.craco.commitment.HashThenCommitCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.*;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Stream;

public class CommitmentSchemeParams {
    private static final int NUMBER_OF_MESSAGES = 3;
    private static final int SECURITY_PARAM = 260;

    public static Collection<StandaloneTestParams> get() {

        PedersenCommitmentSchemePublicParametersGen pedersenCommitmentSchemePublicParametersGen = new
                PedersenCommitmentSchemePublicParametersGen();
        PedersenCommitmentScheme scheme =
                new PedersenCommitmentScheme(pedersenCommitmentSchemePublicParametersGen.setup(SECURITY_PARAM,
                        NUMBER_OF_MESSAGES, true));
        FixedRValuePedersenCommitmentTestScheme testScheme =
                new FixedRValuePedersenCommitmentTestScheme(pedersenCommitmentSchemePublicParametersGen
                        .setup(SECURITY_PARAM,
                                NUMBER_OF_MESSAGES, true));

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        PedersenCommitmentPair pair = getRandomPair(scheme.getPp().getP(), scheme);
        toReturn.add(new StandaloneTestParams(PedersenPublicParameters.class, scheme.getPp()));
        toReturn.add(new StandaloneTestParams(PedersenCommitmentScheme.class, scheme));
        toReturn.add(new StandaloneTestParams(FixedRValuePedersenCommitmentTestScheme.class, testScheme));
        toReturn.add(new StandaloneTestParams(PedersenCommitmentPair.class, pair));
        toReturn.add(new StandaloneTestParams(PedersenOpenValue.class, pair.getOpenValue()));
        toReturn.add(new StandaloneTestParams(PedersenCommitmentValue.class, pair.getCommitmentValue()));
        toReturn.add(new StandaloneTestParams(HashThenCommitCommitmentScheme.class, new
                HashThenCommitCommitmentScheme(testScheme,
                new SHA256HashFunction())));
        return toReturn;
    }

    private static PedersenCommitmentPair getRandomPair(BigInteger p, PedersenCommitmentScheme scheme) {
        Zp zp = new Zp(p);
        UniqueByteRepresentable[] messages = Stream.generate(zp::getUniformlyRandomUnit)
                .limit(scheme.getPp().getH().length)
                .toArray(UniqueByteRepresentable[]::new);
        MessageBlock messageBlock = new MessageBlock();
        Arrays.stream(messages).forEach(element -> messageBlock.add(new RingElementPlainText((Zp.ZpElement) element)));
        return scheme.commit(messageBlock);
    }
}
