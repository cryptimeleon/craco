package de.upb.crypto.craco.protocols.base;

import de.upb.crypto.craco.protocols.TwoPartyProtocol;

/**
 * A minimal implementation of {@link TwoPartyProtocol}.
 */
public abstract class BaseProtocol implements TwoPartyProtocol {
    protected String firstMessageRole;
    protected String otherRole;

    public BaseProtocol(String firstMessageRole, String otherRole) {
        this.firstMessageRole = firstMessageRole;
        this.otherRole = otherRole;
    }

    @Override
    public String getFirstMessageRole() {
        return firstMessageRole;
    }

    @Override
    public String[] getRoleNames() {
        return new String[] {firstMessageRole, otherRole};
    }
}
