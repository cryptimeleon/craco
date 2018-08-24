package de.upb.crypto.craco.abe.accessStructure.util;

public class Pair<T1 extends Comparable<T1>, T2> implements
        Comparable<Pair<T1, T2>> {

    private T1 first;

    private T2 second;

    public Pair(T1 first, T2 second) {
        this.first = first;
        this.second = second;
    }

    @Override
    public int compareTo(Pair<T1, T2> o) {
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
