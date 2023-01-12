package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

/**
 * An implementation of the gamma binding commitment scheme presented in [1]
 * While the scheme is intended to be a building block of the larger SPS scheme
 * {@link org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme},
 * the implementation can be used on its own, where it is gamma-collision resistant
 * under the Double Pairing assumption as defined in [1].
 *
 *
 * Note: The calculation of the commitments differs slightly when the scheme is used in the context of
 * {@link org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme}:
 *      As the scheme combines {@link org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15CommitmentScheme} -- which is
 *      based on this scheme -- with {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme},
 *      the scheme must calculate 2 additional elements for its commitments (with are then signed by XSIG).
 *
 *
 * [1] Abe et al.: Fully Structure-Preserving Signatures and Shrinking Commitments.
 * https://eprint.iacr.org/2015/076.pdf
 *
 */