package de.upb.crypto.craco.abe.interfaces;

import de.upb.crypto.math.structures.zn.Zp.ZpElement;

/**
 * This is a class for storing shares and constant of a linear secret sharing scheme. The <code>value</code> is the
 * constant/share and the other two value are identifier. The first identifier is the party linked to this share and
 * the second identifier gives additional information about the row (MSP) or leaf (threshold tree) the share belong to.
 *
 * @param <E> Type of the party
 * @author pschleiter
 */
@Deprecated
public class Triple<E> {

    private ZpElement value;

    private E identifierOne;

    private Integer identifierTwo;

    public Triple() {

    }

    public Triple(ZpElement value, E identifierOne, Integer identifierTwo) {
        this.value = value;
        this.identifierOne = identifierOne;
        this.identifierTwo = identifierTwo;
    }

    public ZpElement getValue() {
        return value;
    }

    public void setValue(ZpElement value) {
        this.value = value;
    }

    public E getIdentifierOne() {
        return identifierOne;
    }

    public void setIdentifierOne(E identifierOne) {
        this.identifierOne = identifierOne;
    }

    public Integer getIdentifierTwo() {
        return identifierTwo;
    }

    public void setIdentifierTwo(Integer identifierTwo) {
        this.identifierTwo = identifierTwo;
    }

    @Override
    public String toString() {
        return "( " + value.toString() + " , " + identifierOne.toString() + " , " + identifierTwo.toString() + " )";
    }

}
