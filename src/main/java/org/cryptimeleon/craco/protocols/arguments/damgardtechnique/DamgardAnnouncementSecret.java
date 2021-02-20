package org.cryptimeleon.craco.protocols.arguments.damgardtechnique;

import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.protocols.arguments.sigma.Announcement;
import org.cryptimeleon.craco.protocols.arguments.sigma.AnnouncementSecret;

public class DamgardAnnouncementSecret implements AnnouncementSecret {
    final AnnouncementSecret innerAnnouncementSecret;
    final Announcement innerAnnouncement;
    final CommitmentPair commitment;

    public DamgardAnnouncementSecret(AnnouncementSecret innerAnnouncementSecret, Announcement innerAnnouncement, CommitmentPair commitment) {
        this.innerAnnouncementSecret = innerAnnouncementSecret;
        this.innerAnnouncement = innerAnnouncement;
        this.commitment = commitment;
    }
}
