package net.corda.core.identity

import net.corda.core.internal.toX509CertHolder
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import java.security.PublicKey
import java.security.cert.CertPath

/**
 * A full party plus the X.509 certificate and path linking the party back to a trust root. Equality of
 * [PartyAndCertificate] instances is based on the party only, as certificate and path are data associated with the party,
 * not part of the identifier themselves.
 */
//TODO Is LegalIdentity a better name, or VerifiableIdentity?
class PartyAndCertificate(val certPath: CertPath) {
    @Transient val certificate: X509CertificateHolder = certPath.certificates[0].toX509CertHolder()
    @Transient val party: Party = Party(certificate)

    val owningKey: PublicKey get() = party.owningKey
    val name: X500Name get() = party.name

    operator fun component1(): Party = party
    operator fun component2(): X509CertificateHolder = certificate

    override fun equals(other: Any?): Boolean = other === this || other is PartyAndCertificate && other.party == party
    override fun hashCode(): Int = party.hashCode()
    override fun toString(): String = party.toString()
}
