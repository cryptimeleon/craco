package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.sig.sps.SPSPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import java.util.Objects;

public class SPSPOSPublicParameters extends SPSPublicParameters {

    /**
     * Message Length l in the paper
     */
    @Represented
    protected Integer numberOfMessages;




    public SPSPOSPublicParameters(BilinearGroup bilinearGroup, int numberOfMessages) {
        super(bilinearGroup);
        this.numberOfMessages = numberOfMessages;
    }

    public SPSPOSPublicParameters(Representation repr) { super(repr); }




    public Integer getMessageLength(){ return numberOfMessages; }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SPSPOSPublicParameters that = (SPSPOSPublicParameters) o;
        return Objects.equals(numberOfMessages, that.numberOfMessages);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), numberOfMessages);
    }

}
