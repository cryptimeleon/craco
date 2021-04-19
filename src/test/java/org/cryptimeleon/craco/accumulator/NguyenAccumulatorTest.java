package org.cryptimeleon.craco.accumulator;

import org.cryptimeleon.craco.accumulator.nguyen.*;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.junit.Before;
import org.junit.Test;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.*;


public class NguyenAccumulatorTest {

    private NguyenAccumulatorScheme scheme;
    // identity for witnesses and verify
    private Zn.ZnElement singleValue;
    // set containing only single identity
    private Set<Zn.ZnElement> singleIdentitySet;
    // set containing single identity
    private Set<Zn.ZnElement> multipleIdentities;
    // set containing too many identities
    private Set<Zn.ZnElement> tooLargeSet;
    private Zn zn;

    @Before
    public void setup() {
        // maximum of accumulatable identities
        int numberIdentities = 100;
        BilinearGroup group = new DebugBilinearGroup(128, BilinearGroup.Type.TYPE_3);
        scheme = NguyenAccumulatorScheme.setup(group, numberIdentities);
        zn = group.getZn();

        singleValue = zn.getUniformlyRandomElement();
        singleIdentitySet = new HashSet<>(Arrays.asList(singleValue));
        multipleIdentities = new LinkedHashSet<>(singleIdentitySet);
        Stream.generate(() -> zn.getUniformlyRandomElement()).limit(numberIdentities - 3).collect(Collectors.toCollection(() -> multipleIdentities));
        tooLargeSet = new LinkedHashSet<>(singleIdentitySet);
        Stream.generate(() -> zn.getUniformlyRandomElement()).limit(numberIdentities)
                .collect(Collectors.toCollection(() -> tooLargeSet));
    }

    /**
     * Test checking that a {@link NguyenDigest} is calculated
     */
    @Test
    public void testCreate() {
        NguyenDigest value = scheme.createDigest(singleIdentitySet);
        NguyenDigest valueMultiple = scheme.createDigest(multipleIdentities);
        assertNotNull(value);
        assertNotNull(valueMultiple);
    }

    @Test
    public void testVerify() {
        AccumulatorDigest digest = scheme.createDigest(multipleIdentities);
        NguyenWitness witness = scheme.createWitness(digest, multipleIdentities, singleValue);
        assertNotNull(witness);
        assertTrue(scheme.verify(digest, singleValue, witness));
    }

    @Test
    public void testInsert() {
        Set<Zn.ZnElement> oldSet = multipleIdentities;
        NguyenDigest oldAcc = scheme.createDigest(oldSet);

        Zn.ZnElement additionalValue;
        do {
            additionalValue = zn.getUniformlyRandomElement();
        } while (oldSet.contains(additionalValue));
        NguyenDigest newAcc = (NguyenDigest) scheme.insert(oldAcc, oldSet, additionalValue);
        HashSet<Zn.ZnElement> newSet = new HashSet<>(oldSet);
        newSet.add(additionalValue);
        NguyenWitness oldWitness = scheme.createWitness(oldAcc, oldSet, singleValue);

        NguyenWitness newWitness = scheme.updateWitness(oldAcc, newAcc, oldSet, newSet, singleValue, oldWitness);
        assertNotNull(newWitness);
        assertTrue(scheme.verify(newAcc, singleValue, newWitness));
    }

    @Test
    public void testDelete() {
        Set<Zn.ZnElement> oldSet = multipleIdentities;
        NguyenDigest oldAcc = scheme.createDigest(oldSet);

        Zn.ZnElement valueToRemove = null;
        for (Zn.ZnElement val : oldSet) {
            if (!val.equals(singleValue)) {
                valueToRemove = val;
                break;
            }
        }

        NguyenDigest newAcc = (NguyenDigest) scheme.delete(oldAcc, oldSet, valueToRemove);
        HashSet<Zn.ZnElement> newSet = new HashSet<>(oldSet);
        newSet.remove(valueToRemove);
        NguyenWitness oldWitness = scheme.createWitness(oldAcc, oldSet, singleValue);

        NguyenWitness newWitness = scheme.updateWitness(oldAcc, newAcc, oldSet, newSet, singleValue, oldWitness);
        assertNotNull(newWitness);
        assertTrue(scheme.verify(newAcc, singleValue, newWitness));
    }
}
