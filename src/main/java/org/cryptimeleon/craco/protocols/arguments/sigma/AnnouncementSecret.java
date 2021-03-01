package org.cryptimeleon.craco.protocols.arguments.sigma;

/**
 * A private intermediate value (never leaves the prover's JVM) used to generate consistent pairs of announcement and response.
 */
public interface AnnouncementSecret {
    static EmptyAnnouncementSecret EMPTY = new EmptyAnnouncementSecret();
    class EmptyAnnouncementSecret implements AnnouncementSecret {
        private EmptyAnnouncementSecret() {}
    }
}
