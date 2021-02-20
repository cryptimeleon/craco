package org.cryptimeleon.craco.protocols.arguments.sigma.instance;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.InteractiveArgumentInstance;
import org.cryptimeleon.craco.protocols.arguments.sigma.*;

public abstract class SigmaProtocolInstance implements InteractiveArgumentInstance {
    protected SigmaProtocol protocol;
    protected CommonInput commonInput;
    protected SecretInput secretInput;
    protected AnnouncementSecret announcementSecret;
    protected Announcement announcement;
    protected Challenge challenge;
    protected Response response;

    protected SigmaProtocolInstance(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
        this.protocol = protocol;
        this.commonInput = commonInput;
        this.secretInput = secretInput;
    }

    protected SigmaProtocolInstance(SigmaProtocol protocol, CommonInput commonInput) {
        this.protocol = protocol;
        this.commonInput = commonInput;
    }


    @Override
    public SigmaProtocol getProtocol() {
        return protocol;
    }

    @Override
    public boolean isAccepting() {
        return protocol.checkTranscript(commonInput, announcement, challenge, response);
    }
}
