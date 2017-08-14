package net.corda.core.node

import net.corda.core.identity.Party
import net.corda.core.identity.PartyAndCertificate
import net.corda.core.node.services.ServiceInfo
import net.corda.core.node.services.ServiceType
import net.corda.core.serialization.CordaSerializable
import net.corda.core.utilities.NetworkHostAndPort

/**
 * Information for an advertised service including the service specific identity information.
 * The identity can be used in flows and is distinct from the Node's legalIdentity
 */
@CordaSerializable
data class ServiceEntry(val info: ServiceInfo, val party: Party)

/**
 * Info about a network node that acts on behalf of some form of contract party.
 */
// TODO We currently don't support multi-IP/multi-identity nodes, we only left slots in the data structures.
@CordaSerializable
data class NodeInfo(val addresses: List<NetworkHostAndPort>,
                    val legalIdentityAndCert: PartyAndCertificate, //TODO This field will be removed in future PR which gets rid of services.
                    val platformVersion: Int,
                    val advertisedServices: List<ServiceEntry> = emptyList(),
                    val worldMapLocation: WorldMapLocation? = null) {
    init {
        require(advertisedServices.none { it.party == legalIdentity }) {
            "Service identities must be different from node legal identity"
        }
    }

    val legalIdentity: Party get() = legalIdentityAndCert.party
    val notaryIdentity: Party get() = advertisedServices.single { it.info.type.isNotary() }.party
    fun serviceIdentities(type: ServiceType): List<Party> {
        return advertisedServices.mapNotNull { if (it.info.type.isSubTypeOf(type)) it.party else null }
    }
}
