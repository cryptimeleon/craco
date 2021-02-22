package org.cryptimeleon.craco.accumulator;

import org.cryptimeleon.craco.accumulator.nguyen.*;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.junit.Before;
import org.junit.Test;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.*;


public class NguyenAccumulatorTest {

    private NguyenAccumulator accumulator;
    // identity for witnesses and verify
    private NguyenAccumulatorIdentity singleIdentity;
    // set containing only single identity
    private Set<NguyenAccumulatorIdentity> singleIdentitySet;
    // set containing single identity
    private Set<NguyenAccumulatorIdentity> multipleIdentities;
    // set containing too many identities
    private Set<NguyenAccumulatorIdentity> tooLargeSet;
    private Zp zp;

    @Before
    public void setup() {
        NguyenAccumulatorPublicParametersGen ppGen = new NguyenAccumulatorPublicParametersGen();
        // maximum of accumulatable identities
        int numberIdentities = 100;
        NguyenAccumulatorPublicParameters pp = ppGen.setup(260, numberIdentities, true);
        accumulator = new NguyenAccumulator(pp);
        zp = accumulator.getPp().getUniverse().get(0).getZp();
        singleIdentity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        singleIdentitySet = new HashSet<>(Arrays.asList(singleIdentity));
        multipleIdentities = new LinkedHashSet<>(singleIdentitySet);
        Stream.generate(() -> new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement())).limit(numberIdentities -
                3).collect(Collectors.toCollection(() -> multipleIdentities));
        tooLargeSet = new LinkedHashSet<>(singleIdentitySet);
        Stream.generate(() -> new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement())).limit(numberIdentities)
                .collect(Collectors.toCollection(() -> tooLargeSet));
    }

    /**
     * Test checking that a {@link NguyenAccumulatorValue} is calculated
     */
    @Test
    public void testCreate() {
        NguyenAccumulatorValue value = accumulator.create(singleIdentitySet);
        NguyenAccumulatorValue valueMultiple = accumulator.create(multipleIdentities);
        assertNotNull(value);
        assertNotNull(valueMultiple);
    }

    /**
     * Test checking that verify accepts a {@link NguyenWitness} for a {@link NguyenAccumulatorIdentity} in an
     * accumulated set.
     */
    @Test
    public void testVerify() {
        Set<NguyenAccumulatorIdentity> set = multipleIdentities;
        NguyenAccumulatorValue value = accumulator.create(set);
        NguyenAccumulatorIdentity identity = singleIdentity;
        NguyenWitness witness = (NguyenWitness) accumulator.createWitness(set, identity);
        assertNotNull(witness);
        assertTrue(accumulator.verify(value, identity, witness));
    }

    /**
     * Test checking that after inserting a {@link NguyenAccumulatorIdentity} verify still accepts a
     * {@link NguyenWitness} for a {@link NguyenAccumulatorIdentity} in an accumulated set.
     */
    @Test
    public void testInsert() {
        Set<NguyenAccumulatorIdentity> set = multipleIdentities;
        NguyenAccumulatorValue value = accumulator.create(set);
        NguyenAccumulatorIdentity identity;
        do {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (identity.equals(singleIdentity) && !set.contains(identity));
        value = (NguyenAccumulatorValue) accumulator.insert(value, accumulator.getIdentitySet(), identity);
        set = accumulator.getIdentitySet();
        NguyenWitness witness = (NguyenWitness) accumulator.createWitness(set, identity);
        assertNotNull(witness);
        assertTrue(accumulator.verify(value, identity, witness));
    }

    /**
     * Test checking that after deleting a {@link NguyenAccumulatorIdentity} verify still accepts a
     * {@link NguyenWitness} for a {@link NguyenAccumulatorIdentity} in an accumulated set.
     */
    @Test
    public void testDelete() {
        Set<NguyenAccumulatorIdentity> set = multipleIdentities;
        NguyenAccumulatorIdentity identity;
        do {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (identity.equals(singleIdentity) && !set.contains(identity));
        set.add(identity);
        NguyenAccumulatorValue value = accumulator.create(set);
        value = (NguyenAccumulatorValue) accumulator.delete(value, accumulator.getIdentitySet(), identity);
        set = accumulator.getIdentitySet();
        NguyenWitness witness = (NguyenWitness) accumulator.createWitness(set, singleIdentity);
        assertNotNull(witness);
        assertTrue(accumulator.verify(value, singleIdentity, witness));

    }

    /**
     * Test checking that creation of a {@link NguyenWitness} for a{@link NguyenAccumulatorIdentity} actually equals
     * the {@link NguyenAccumulatorValue} after deleting the same {@link NguyenAccumulatorIdentity} from the set.
     */
    @Test
    public void witCreateEqualsDelete() {
        Set<NguyenAccumulatorIdentity> set = multipleIdentities;
        NguyenAccumulatorIdentity identity;
        do {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (identity.equals(singleIdentity) && !set.contains(identity));
        set.add(identity);
        NguyenAccumulatorValue value = accumulator.create(set);


        NguyenWitness witnessIdentityBeforeDelete = (NguyenWitness) accumulator.createWitness(set, identity);
        value = (NguyenAccumulatorValue) accumulator.delete(value, set, identity);
        assertNotNull(witnessIdentityBeforeDelete);
        assertEquals(value.getValue(), witnessIdentityBeforeDelete.getValue());
    }

    /**
     * Test checking that update works for a single deletion and afterwards multiple deletions of
     * {@link NguyenAccumulatorIdentity}.
     */
    @Test
    public void testUpdateDelete() {
        Set<NguyenAccumulatorIdentity> set = multipleIdentities;
        NguyenAccumulatorIdentity identity;
        do {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (identity.equals(singleIdentity) && !set.contains(identity));
        set.add(identity);
        NguyenAccumulatorValue value = accumulator.create(set);
        NguyenWitness witness = (NguyenWitness) accumulator.createWitness(set, singleIdentity);

        LinkedHashSet<NguyenAccumulatorIdentity> oldSet = new LinkedHashSet<>(set);
        NguyenAccumulatorValue currentValue = (NguyenAccumulatorValue) accumulator.delete(accumulator
                .getAccumulatorValue(), accumulator.getIdentitySet(), identity);

        NguyenWitness updatedWitness = accumulator.update(value, currentValue, oldSet, accumulator.getIdentitySet(),
                singleIdentity, witness);

        assertNotNull(witness);
        assertTrue("Update failed for single deletions.",
                accumulator.verify(currentValue, singleIdentity, updatedWitness));

        List<NguyenAccumulatorIdentity> accumulatedIdentities = new ArrayList<>(accumulator.getIdentitySet());
        for (int i = 0; i < 5; i++) {
            if (!accumulatedIdentities.get(i).equals(singleIdentity) && !set.contains(identity)) {
                currentValue = (NguyenAccumulatorValue) accumulator.delete(accumulator.getAccumulatorValue(),
                        accumulator.getIdentitySet(), accumulatedIdentities.get(i));
            }
        }
        updatedWitness = accumulator.update(value, currentValue, oldSet, accumulator.getIdentitySet(),
                singleIdentity, witness);

        assertNotNull(witness);
        assertTrue("Update failed for multiple deletions.",
                accumulator.verify(currentValue, singleIdentity, updatedWitness));
    }

    /**
     * Test checking that update works for a single insertion and afterwards multiple insertions of
     * {@link NguyenAccumulatorIdentity}.
     */
    @Test
    public void testUpdateInsert() {
        Set<NguyenAccumulatorIdentity> set = multipleIdentities;
        NguyenAccumulatorValue value = accumulator.create(set);
        NguyenWitness witness = (NguyenWitness) accumulator.createWitness(set, singleIdentity);
        LinkedHashSet<NguyenAccumulatorIdentity> oldSet = new LinkedHashSet<>(set);
        NguyenAccumulatorIdentity identity;
        do {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (identity.equals(singleIdentity) && !set.contains(identity));
        NguyenAccumulatorValue currentValue = (NguyenAccumulatorValue) accumulator.insert(accumulator
                .getAccumulatorValue(), accumulator.getIdentitySet(), identity);
        NguyenWitness updatedWitness = accumulator.update(value, currentValue, oldSet, accumulator.getIdentitySet(),
                singleIdentity, witness);
        assertNotNull(witness);
        assertTrue("Update failed for single insert.",
                accumulator.verify(currentValue, singleIdentity, updatedWitness));
        while (accumulator.getIdentitySet().size() < accumulator.getPp().getUpperBoundForAccumulatableIdentities()
                .intValue()) {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
            if (!identity.equals(singleIdentity) && !set.contains(identity)) {
                currentValue = (NguyenAccumulatorValue) accumulator.insert(accumulator.getAccumulatorValue(),
                        accumulator.getIdentitySet(), identity);
            }
        }
        updatedWitness = accumulator.update(value, currentValue, oldSet, accumulator.getIdentitySet(),
                singleIdentity, witness);
        assertNotNull(witness);
        assertTrue("Update failed for multiple insertions.",
                accumulator.verify(currentValue, singleIdentity, updatedWitness));
    }

    /**
     * Test checking that update works for multiple insertions and deletions of {@link NguyenAccumulatorIdentity}.
     */
    @Test
    public void testUpdate() {
        Set<NguyenAccumulatorIdentity> set = multipleIdentities;
        NguyenAccumulatorIdentity identity;
        do {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (identity.equals(singleIdentity) && !set.contains(identity));
        set.add(identity);
        NguyenAccumulatorIdentity identity2;
        do {
            identity2 = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (identity2.equals(singleIdentity) && !set.contains(identity2));
        NguyenAccumulatorValue value = accumulator.create(set);
        LinkedHashSet<NguyenAccumulatorIdentity> oldSet = new LinkedHashSet<>(set);
        NguyenWitness witness = (NguyenWitness) accumulator.createWitness(set, singleIdentity);

        NguyenAccumulatorValue currentValue;

        if (accumulator.getIdentitySet().size() < accumulator.getPp().getUpperBoundForAccumulatableIdentities()
                .intValue()) {
            accumulator.insert(accumulator.getAccumulatorValue(), accumulator.getIdentitySet(), identity2);
        }

        List<NguyenAccumulatorIdentity> accumulatedIdentities = new ArrayList<>(accumulator.getIdentitySet());
        for (int i = 0; i < 5; i++) {
            if (!accumulatedIdentities.get(i).equals(singleIdentity) && !set.contains(identity)) {
                accumulator.delete(accumulator.getAccumulatorValue(), accumulator.getIdentitySet(),
                        accumulatedIdentities.get(i));
            }
        }

        if (accumulator.getIdentitySet().size() < accumulator.getPp().getUpperBoundForAccumulatableIdentities()
                .intValue()) {
            accumulator.insert(accumulator.getAccumulatorValue(), accumulator.getIdentitySet(), new
                    NguyenAccumulatorIdentity(zp.getUniformlyRandomElement()));
        }
        currentValue = (NguyenAccumulatorValue) accumulator.delete(accumulator.getAccumulatorValue(), accumulator
                .getIdentitySet(), identity);

        NguyenWitness updatedWitness = accumulator.update(value, currentValue, oldSet, accumulator.getIdentitySet(),
                singleIdentity, witness);

        assertNotNull(witness);
        assertTrue("Update failed for multiple operations.",
                accumulator.verify(currentValue, singleIdentity, updatedWitness));
    }

    /**
     * Test checking for expected exceptions
     */
    @Test
    public void checkForExceptions() {

        // expected exception because of the empty set
        boolean emptyLeadsToException = false;
        singleIdentitySet.remove(singleIdentity);
        try {
            accumulator.create(singleIdentitySet);
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) emptyLeadsToException = true;
        }
        assertTrue(emptyLeadsToException);

        // expected exception because of the too large set
        boolean tooLargeSetLeadsToException = false;
        try {
            accumulator.create(tooLargeSet);
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) tooLargeSetLeadsToException = true;
        }
        assertTrue(tooLargeSetLeadsToException);
    }

    /**
     * Test checking for expected errors
     */
    @Test
    public void checkErrorCases() {

        NguyenAccumulatorValue value = accumulator.create(multipleIdentities);
        assertNotNull(value);

        // inserting accumulated Identity should return null
        assertNull(accumulator.insert(accumulator.getIdentitySet(), singleIdentity));

        // deleting an identity that is not accumulated should return null
        NguyenAccumulatorIdentity identity;
        do {
            identity = new NguyenAccumulatorIdentity(zp.getUniformlyRandomElement());
        } while (accumulator.getIdentitySet().contains(identity));
        assertNull(accumulator.delete(accumulator.getIdentitySet(), identity));


        // verify should be false for wrong parameter combinations
        List<NguyenAccumulatorIdentity> accumulatedIdentities = new ArrayList<>(accumulator.getIdentitySet());

        NguyenAccumulatorIdentity identity1 = accumulatedIdentities.get(0);
        NguyenAccumulatorIdentity identity2 = accumulatedIdentities.get(1);
        NguyenWitness witness1 = (NguyenWitness) accumulator.createWitness(accumulator.getIdentitySet(), identity1);
        NguyenWitness witness2 = (NguyenWitness) accumulator.createWitness(accumulator.getIdentitySet(), identity2);
        NguyenAccumulatorValue valueDifferent;
        do {
            valueDifferent = new NguyenAccumulatorValue(value.getValue().getStructure().getUniformlyRandomNonNeutral());
        } while (value.equals(valueDifferent));
        assertFalse(accumulator.verify(value, identity1, witness2));
        assertFalse(accumulator.verify(value, identity2, witness1));
        assertFalse(accumulator.verify(valueDifferent, identity1, witness1));
        assertFalse(accumulator.verify(valueDifferent, identity1, witness2));
        assertFalse(accumulator.verify(valueDifferent, identity2, witness1));
        assertFalse(accumulator.verify(valueDifferent, identity2, witness2));
    }
}
