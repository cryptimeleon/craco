package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.math.structures.cartesian.Vector;

import java.util.List;

/**
 * A private intermediate value (never leaves the prover's JVM) used to generate consistent pairs of announcement and response.
 */
public interface AnnouncementSecret {
    static EmptyAnnouncementSecret EMPTY = new EmptyAnnouncementSecret();
    class EmptyAnnouncementSecret implements AnnouncementSecret {
        private EmptyAnnouncementSecret() {}
    }

    public class AnnouncementSecretVector extends Vector<AnnouncementSecret> implements AnnouncementSecret {

        public AnnouncementSecretVector(AnnouncementSecret... announcementSecrets) {
            super(announcementSecrets);
        }

        public AnnouncementSecretVector(List<? extends AnnouncementSecret> announcementSecrets) {
            super(announcementSecrets);
        }
    }
}
