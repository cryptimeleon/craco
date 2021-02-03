package de.upb.crypto.craco.protocols.base;

import de.upb.crypto.craco.protocols.TwoPartyProtocol;
import de.upb.crypto.craco.protocols.TwoPartyProtocolInstance;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.HashMap;

public abstract class BaseProtocolInstance implements TwoPartyProtocolInstance {
    static final String HIGH_LEVEL_PROT_MSGS = "high_level_prot_msgs";

    private final BaseProtocol protocol;
    private final String role;
    private int round = 0;
    private HashMap<String, TwoPartyProtocolInstance> newSubprotocolInstances = new HashMap<>();
    private final HashMap<String, TwoPartyProtocolInstance> runningSubprotocolInstances = new HashMap<>();
    private HashMap<String, Representation> valuesToSendNext = new HashMap<>();
    private final HashMap<String, Representation> valuesReceived = new HashMap<>();
    private boolean highLevelWantsTerminate = false;

    public BaseProtocolInstance(BaseProtocol protocol, String role) {
        this.protocol = protocol;
        this.role = role;
        this.round = this.sendsFirstMessage() ? 0 : 1;
    }

    @Override
    public TwoPartyProtocol getProtocol() {
        return protocol;
    }

    protected void runSubprotocolConcurrently(String instanceName, TwoPartyProtocolInstance instance) {
        newSubprotocolInstances.put(instanceName, instance);
    }

    protected void send(String id, Representation repr) {
        if (id == null || id.equals(HIGH_LEVEL_PROT_MSGS))
            throw new IllegalArgumentException("illegal id");
        valuesToSendNext.put(id, repr);
    }

    protected Representation receive(String id) {
        Representation received = valuesReceived.get(id);
        valuesReceived.remove(id);
        return received;
    }

    protected void terminate() {
        this.highLevelWantsTerminate = true;
    }

    @Override
    public Representation nextMessage(Representation received) {
        ObjectRepresentation toSend = new ObjectRepresentation(); //what to send this round.

        //High-level protocol receiving (send()/receive() methods)
        if (received != null) {
            received.obj().get(HIGH_LEVEL_PROT_MSGS).obj().forEach(e -> {
                valuesReceived.putIfAbsent(e.getKey(), e.getValue()); //don't allow sender to overwrite unretrieved values in the valuesReceived map.
            });
        }

        //Advance subprotocols
        runningSubprotocolInstances.forEach( (name, instance) -> {
            Representation nextMsg = instance.nextMessage(received.obj().get(name));
            if (nextMsg != null)
                toSend.put(name, nextMsg);
        });

        //Call user-defined function for this round
        if (role.equals(getProtocol().getFirstMessageRole()))
            doRoundForFirstRole(round);
        else
            doRoundForSecondRole(round);
        round += 2;

        //High-level protocol sending (send()/receive() methods)
        ObjectRepresentation high_level_prot_msgs = new ObjectRepresentation();
        valuesToSendNext.forEach(high_level_prot_msgs::put);
        valuesToSendNext = new HashMap<>(); //reset for next round
        toSend.put(HIGH_LEVEL_PROT_MSGS, high_level_prot_msgs);

        //Subprotocol handling for newly added sub-protocols
        newSubprotocolInstances.forEach((name, instance) -> {
            if (instance.sendsFirstMessage())
                toSend.put(name, instance.nextMessage(null));
            else {
                Representation nextMsg = instance.nextMessage(received.obj().get(name));
                if (nextMsg != null)
                    toSend.put(name, nextMsg);
            }
            runningSubprotocolInstances.put(name, instance);
        });
        newSubprotocolInstances = new HashMap<>();

        //Housekeeping
        runningSubprotocolInstances.entrySet().removeIf(e -> e.getValue().hasTerminated()); //remove protocols we're done with.

        return toSend;
    }

    protected abstract void doRoundForFirstRole(int round);
    protected abstract void doRoundForSecondRole(int round);

    @Override
    public boolean hasTerminated() {
        return this.highLevelWantsTerminate && runningSubprotocolInstances.isEmpty();
    }

    @Override
    public String getRoleName() {
        return role;
    }
}
