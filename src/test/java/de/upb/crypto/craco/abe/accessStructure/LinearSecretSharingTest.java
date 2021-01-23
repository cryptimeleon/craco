package de.upb.crypto.craco.abe.accessStructure;

import de.upb.crypto.craco.abe.interfaces.LinearSecretSharing;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.craco.secretsharing.ShamirSecretSharing;
import de.upb.crypto.craco.secretsharing.ShamirSecretSharingSchemeProvider;
import de.upb.crypto.craco.secretsharing.ThresholdTreeSecretSharing;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings({"rawtypes", "unchecked"})
@RunWith(Parameterized.class)
public class LinearSecretSharingTest {
    protected LinearSecretSharing lsss;
    protected Zp zp;
    protected Supplier<ZpElement> secretSupplier;
    protected Set validShareReceiverSet;
    protected Set invalidShareReceiverSet;


    public LinearSecretSharingTest(TestParams params) {
        this.lsss = params.lsss;
        this.zp = params.zp;
        this.secretSupplier = params.secretSupplier;
        this.validShareReceiverSet = params.validShareReceiverSet;
        this.invalidShareReceiverSet = params.invalidShareReceiverSet;
    }

    @Test
    public final void shareAndReconstructionTest() {
        ZpElement secret = secretSupplier.get();
        Map<Integer, ZpElement> shares = createShares(secret);

        assertTrue(lsss.isQualified(validShareReceiverSet));

        Set<Integer> shareReceiver = lsss.getSharesOfReceivers(validShareReceiverSet);
        Map<Integer, ZpElement> validShares = shares.entrySet().stream()
                .filter(entry -> shareReceiver.contains(entry.getKey()))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue
                ));


        ZpElement restored = lsss.reconstruct(validShares);

        assertEquals(secret, restored);
    }

    @Test
    public final void shareAndReconstructionViaSolvingVectorTest() {
        ZpElement secret = secretSupplier.get();
        Map<Integer, ZpElement> shares = createShares(secret);

        assertTrue(lsss.isQualified(validShareReceiverSet));

        Map<Integer, ZpElement> solvingVector = lsss.getSolvingVector(validShareReceiverSet);

        ZpElement restored = shares.entrySet().stream() // look at all shares
                .map(e -> e.getValue().mul(solvingVector
                        .getOrDefault(e.getKey(), lsss.getSharedRing().getZeroElement())))
                .reduce(lsss.getSharedRing().getZeroElement(), ZpElement::add); // add all of them

        assertEquals(secret, restored);
    }


    @Test
    public final void shareCompletionTest() {
        if (invalidShareReceiverSet == null || invalidShareReceiverSet.isEmpty()) {
            return;
        }

        ZpElement secret = secretSupplier.get();
        Map<Integer, ZpElement> shares = createShares(secret);

        Set<Integer> shareReceiver = lsss.getSharesOfReceivers(invalidShareReceiverSet);
        Map<Integer, ZpElement> invalidShares = shares.entrySet().stream()
                .filter(entry -> shareReceiver.contains(entry.getKey()))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue
                ));
        ZpElement anotherSecret = secretSupplier.get();
        Map<Integer, ZpElement> completedShares = lsss.completeShares(anotherSecret, invalidShares);

        assertTrue("completedShares must result in consistent shares", lsss.checkShareConsistency(anotherSecret,
                completedShares));


    }

    private Map<Integer, ZpElement> createShares(ZpElement secret) {
        @SuppressWarnings("unchecked")
        Map<Integer, ZpElement> shares = lsss.getShares(secret);

        try {
            assertTrue("getShares must result in consistent shares", lsss.checkShareConsistency(secret, shares));
        } catch (Exception ex) {
            assertTrue("checkShareConsistency must only throw UnsupportedOperationException",
                    ex instanceof UnsupportedOperationException);
        }

        return shares;

    }

    @Parameters //add (name="Test: {1}") for jUnit 4.12+ to print ring's name to test
    public static Collection<TestParams[]> data() {
        StringAttribute A = new StringAttribute("A");
        StringAttribute B = new StringAttribute("B");
        StringAttribute C = new StringAttribute("C");

        Zp z11 = new Zp(BigInteger.valueOf(11));

        //Simple AND
        ThresholdPolicy simpleAnd = new ThresholdPolicy(2, A, B);
        Set simpleAndFulfilling = new HashSet<>(Arrays.asList(A, B));
        Set simpleAndNotFulfilling = new HashSet<>(Collections.singletonList(B));

        //Simple OR
        ThresholdPolicy simpleOr = new ThresholdPolicy(1, A, B);
        Set simpleOrFulfilling = new HashSet<>(Collections.singletonList(B));

        //(A or B) and (B or C)
        ThresholdPolicy complex = new ThresholdPolicy(2,
                new ThresholdPolicy(1, A, B),
                new ThresholdPolicy(1, B, C)
        );
        Set complexFulfilling = new HashSet<>(Collections.singletonList(B));
        Set complexNotFulfilling = new HashSet<>(Collections.singletonList(C));

        ThresholdPolicy evenMoreComplex = new ThresholdPolicy(3,
                new ThresholdPolicy(3,
                        B,
                        new ThresholdPolicy(1, A, B),
                        new ThresholdPolicy(1, B, C)
                ),
                new ThresholdPolicy(3,
                        new ThresholdPolicy(1, A, B),
                        new ThresholdPolicy(2, A, B, C),
                        A
                ),
                new ThresholdPolicy(2,
                        new ThresholdPolicy(1, A, C),
                        C,
                        new ThresholdPolicy(2, A, B)
                )
        );
        Set evenMoreComplexFulfilling = new HashSet<>(Arrays.asList(A, B));
        Set evenMoreComplexNotFulfilling = new HashSet<>(Collections.singletonList(C));

        SecretSharingSchemeProvider lsssCreation = new ShamirSecretSharingSchemeProvider();

        //Collect parameters
        TestParams params[][] = new TestParams[][]{
                {new TestParams(new MonotoneSpanProgram(simpleAnd, z11), simpleAndFulfilling)},
                {new TestParams(new MonotoneSpanProgram(simpleOr, z11), simpleOrFulfilling)},
                {new TestParams(new MonotoneSpanProgram(complex, z11), complexFulfilling)},
                {new TestParams(new ShamirSecretSharing(simpleAnd, z11), simpleAndFulfilling, simpleAndNotFulfilling)},
                {new TestParams(new ShamirSecretSharing(simpleOr, z11), simpleOrFulfilling)},
                {new TestParams(new ThresholdTreeSecretSharing(complex, z11, lsssCreation), complexFulfilling,
                        complexNotFulfilling)},
                {new TestParams(new ThresholdTreeSecretSharing(evenMoreComplex, z11, lsssCreation),
                        evenMoreComplexFulfilling, evenMoreComplexNotFulfilling)}
        };
        return Arrays.asList(params);
    }

    private static class TestParams {
        LinearSecretSharing<?> lsss;
        Zp zp;
        Supplier<ZpElement> secretSupplier;
        Set validShareReceiverSet;
        Set invalidShareReceiverSet;

        @SuppressWarnings("unused")
        public TestParams(LinearSecretSharing<?> lsss, Set validShareReceiverSet, Supplier<ZpElement> secretSupplier) {
            this.lsss = lsss;
            this.secretSupplier = secretSupplier;
            this.zp = lsss.getSharedRing();
            this.validShareReceiverSet = validShareReceiverSet;
        }

        public TestParams(LinearSecretSharing<?> lsss, Set validShareReceiverSet) {
            this(lsss, validShareReceiverSet, lsss.getSharedRing()::getUniformlyRandomElement);
        }

        public TestParams(LinearSecretSharing<?> lsss, Set validShareReceiverSet, Set
                invalidShareReceiverSet) {
            this(lsss, validShareReceiverSet);
            this.invalidShareReceiverSet = invalidShareReceiverSet;
        }

        @Override
        public String toString() {
            return lsss.toString();
        }
    }
}
