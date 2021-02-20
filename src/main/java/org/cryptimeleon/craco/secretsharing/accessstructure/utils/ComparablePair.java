package org.cryptimeleon.craco.secretsharing.accessstructure.utils;

/**
 * A pair class which allows for comparisons via the first element.
 *
 * @param <T1> the type of the first element which must be comparable
 * @param <T2> the type of the second element
 */
public class ComparablePair<T1 extends Comparable<T1>, T2> implements
        Comparable<ComparablePair<T1, T2>> {

    private T1 first;

    private T2 second;

    public ComparablePair(T1 first, T2 second) {
        this.first = first;
        this.second = second;
    }

    @Override
    public int compareTo(ComparablePair<T1, T2> o) {
        return first.compareTo(o.getFirst());
    }

    public T1 getFirst() {
        return first;
    }

    public T2 getSecond() {
        return second;
    }

    public void setFirst(T1 first) {
        this.first = first;
    }

    public void setSecond(T2 second) {
        this.second = second;
    }

    @Override
    public String toString() {
        return "(" + first.toString() + ", " + second.toString() + ")";
    }

}
