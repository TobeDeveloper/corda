package net.corda.node.services.vault

import net.corda.core.contracts.ContractState
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.AbstractParty
import net.corda.core.node.services.Vault
import net.corda.core.schemas.MappedSchema
import net.corda.core.schemas.PersistentState
import net.corda.core.serialization.CordaSerializable
import net.corda.core.utilities.OpaqueBytes
import java.time.Instant
import java.util.*
import javax.persistence.*

/**
 * JPA representation of the core Vault Schema
 */
object VaultSchema

/**
 * First version of the Vault ORM schema
 */
@CordaSerializable
object VaultSchemaV1 : MappedSchema(schemaFamily = VaultSchema.javaClass, version = 1,
                                    mappedTypes = listOf(VaultStates::class.java, VaultLinearStates::class.java, VaultFungibleStates::class.java)) {
    @Entity
    @Table(name = "vault_states",
            indexes = arrayOf(Index(name = "state_status_idx", columnList = "state_status")))
    class VaultStates(
            /** refers to the X500Name of the notary a state is attached to */
            @Column(name = "notary_name")
            var notaryName: AbstractParty,

            /** references a concrete ContractState that is [QueryableState] and has a [MappedSchema] */
            @Column(name = "contract_state_class_name")
            var contractStateClassName: String,

            /** refers to serialized transaction Contract State */
            // TODO: define contract state size maximum size and adjust length accordingly
            @Column(name = "contract_state", length = 100000)
            var contractState: ByteArray,

            /** state lifecycle: unconsumed, consumed */
            @Column(name = "state_status")
            var stateStatus: Vault.StateStatus,

            /** refers to timestamp recorded upon entering UNCONSUMED state */
            @Column(name = "recorded_timestamp")
            var recordedTime: Instant,

            /** refers to timestamp recorded upon entering CONSUMED state */
            @Column(name = "consumed_timestamp", nullable = true)
            var consumedTime: Instant?,

            /** used to denote a state has been soft locked (to prevent double spend)
             *  will contain a temporary unique [UUID] obtained from a flow session */
            @Column(name = "lock_id", nullable = true)
            var lockId: String,

            /** refers to the last time a lock was taken (reserved) or updated (released, re-reserved) */
            @Column(name = "lock_timestamp", nullable = true)
            var lockUpdateTime: Instant?
    ) : PersistentState()

    @Entity
    @Table(name = "vault_linear_states",
            indexes = arrayOf(Index(name = "external_id_index", columnList = "external_id"),
                              Index(name = "uuid_index", columnList = "uuid"),
                              Index(name = "deal_reference_index", columnList = "deal_reference")))
    class VaultLinearStates(
            /** [ContractState] attributes */

            /** X500Name of participant parties **/
            @ElementCollection
            @Column(name = "participants")
            var participants: MutableSet<AbstractParty>? = null,
            // Reason for not using Set is described here:
            // https://stackoverflow.com/questions/44213074/kotlin-collection-has-neither-generic-type-or-onetomany-targetentity

            /**
             *  Represents a [LinearState] [UniqueIdentifier]
             */
            @Column(name = "external_id")
            var externalId: String?,

            @Column(name = "uuid", nullable = false)
            var uuid: UUID,

            // TODO: DealState to be deprecated (collapsed into LinearState)

            /** Deal State attributes **/
            @Column(name = "deal_reference")
            var dealReference: String
    ) : PersistentState() {
        constructor(uid: UniqueIdentifier, _dealReference: String, _participants: List<AbstractParty>) :
                this(externalId = uid.externalId,
                     uuid = uid.id,
                     dealReference = _dealReference,
                     participants = _participants.toMutableSet())
    }

    @Entity
    @Table(name = "vault_fungible_states")
    class VaultFungibleStates(
            /** [ContractState] attributes */

            /** X500Name of participant parties **/
            @ElementCollection
            @Column(name = "participants")
            var participants: MutableSet<AbstractParty>? = null,

            /** [OwnableState] attributes */
            @Column(name = "owner_id")
            var owner: AbstractParty,

            /** [FungibleAsset] attributes
             *
             *  Note: the underlying Product being issued must be modelled into the
             *  custom contract itself (eg. see currency in Cash contract state)
             */

            /** Amount attributes */
            @Column(name = "quantity")
            var quantity: Long,

            /** Issuer attributes */

            /** X500Name of issuer party **/
            @Column(name = "issuer_name")
            var issuer: AbstractParty,

            @Column(name = "issuer_reference")
            var issuerRef: ByteArray
    ) : PersistentState() {
        constructor(_owner: AbstractParty, _quantity: Long, _issuerParty: AbstractParty, _issuerRef: OpaqueBytes, _participants: List<AbstractParty>) :
                this(owner = _owner,
                     quantity = _quantity,
                     issuer = _issuerParty,
                     issuerRef = _issuerRef.bytes,
                     participants = _participants.toMutableSet())
    }
}