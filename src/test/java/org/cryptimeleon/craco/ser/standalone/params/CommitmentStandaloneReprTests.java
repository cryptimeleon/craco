package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParametersGen;
import org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15CommitmentScheme;
import org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15CommitmentSchemeTestParameterGenerator;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15CommitmentScheme;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15CommitmentSchemeTestParameterGenerator;
import org.cryptimeleon.craco.sig.sps.CommitmentSchemeParams;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15XSIGPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGPublicParametersGen;
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

    public void testTCGAKOT15() {
        AKOT15SharedPublicParameters pp = AKOT15SharedPublicParametersGen.generateParameters(
                128, 20, true);

        TCGAKOT15CommitmentScheme scheme = new TCGAKOT15CommitmentScheme(pp);

        test(pp);
        test(scheme);

        // test xSIG variant of the scheme

        SPSXSIGPublicParameters ppXSIG = SPSXSIGPublicParametersGen.generatePublicParameters(128, 20, true);
        TCGAKOT15XSIGPublicParameters ppTCGXSIG = new TCGAKOT15XSIGPublicParameters(ppXSIG, 20);

        test(ppTCGXSIG);
    }

    public void testTCAKOT15() {
        AKOT15SharedPublicParameters pp = AKOT15SharedPublicParametersGen.generateParameters(
                128, 20, true);

        TCAKOT15CommitmentScheme scheme = new TCAKOT15CommitmentScheme(pp);

        test(pp);
        test(scheme);
    }

    public void testHashThenCommit() {
        test(new HashThenCommitCommitmentScheme(pedersen, new SHA256HashFunction()));
    }
}
