package net.corda.traderdemo

import net.corda.contracts.CommercialPaper
import net.corda.contracts.asset.Cash
import net.corda.contracts.getCashBalance
import net.corda.core.contracts.Amount
import net.corda.core.contracts.DOLLARS
import net.corda.core.contracts.USD
import net.corda.core.internal.Emoji
import net.corda.core.internal.concurrent.transpose
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.startFlow
import net.corda.core.messaging.vaultQueryBy
import net.corda.core.node.services.vault.QueryCriteria
import net.corda.core.node.services.vault.builder
import net.corda.core.utilities.OpaqueBytes
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.loggerFor
import net.corda.flows.CashIssueFlow
import net.corda.node.services.vault.VaultSchemaV1
import net.corda.testing.DUMMY_NOTARY
import net.corda.testing.contracts.calculateRandomlySizedAmounts
import net.corda.traderdemo.flow.CommercialPaperIssueFlow
import net.corda.traderdemo.flow.SellerFlow
import org.bouncycastle.asn1.x500.X500Name
import java.util.*

/**
 * Interface for communicating with nodes running the trader demo.
 */
class TraderDemoClientApi(val rpc: CordaRPCOps) {
    private companion object {
        val logger = loggerFor<TraderDemoClientApi>()
    }

    val cashCount: Long get() {
        val count = builder { VaultSchemaV1.VaultStates::recordedTime.count() }
        val countCriteria = QueryCriteria.VaultCustomQueryCriteria(count)
        return rpc.vaultQueryBy<Cash.State>(countCriteria).otherResults.single() as Long
    }

    val dollarCashBalance: Amount<Currency> get() = rpc.getCashBalance(USD)

    val commercialPaperCount: Long get() {
        val count = builder { VaultSchemaV1.VaultStates::recordedTime.count() }
        val countCriteria = QueryCriteria.VaultCustomQueryCriteria(count)
        return rpc.vaultQueryBy<CommercialPaper.State>(countCriteria).otherResults.single() as Long
    }

    fun runIssuer(amount: Amount<Currency> = 1100.0.DOLLARS, buyerName: X500Name, sellerName: X500Name, notaryName: X500Name) {
        val ref = OpaqueBytes.of(1)
        val buyer = rpc.partyFromX500Name(buyerName) ?: throw IllegalStateException("Don't know $buyerName")
        val seller = rpc.partyFromX500Name(sellerName) ?: throw IllegalStateException("Don't know $sellerName")
        val notaryLegalIdentity = rpc.partyFromX500Name(DUMMY_NOTARY.name)
                ?: throw IllegalStateException("Unable to locate ${DUMMY_NOTARY.name} in Network Map Service")
        val notaryNode = rpc.nodeIdentityFromParty(notaryLegalIdentity)
                ?: throw IllegalStateException("Unable to locate notary node in network map cache")
        val amounts = calculateRandomlySizedAmounts(amount, 3, 10, Random())
        val anonymous = false
        // issue random amounts of currency up to the requested amount, in parallel
        val resultFutures = amounts.map { pennies ->
            rpc.startFlow(::CashIssueFlow, amount.copy(quantity = pennies), OpaqueBytes.of(1), buyer, notaryNode.notaryIdentity, anonymous).returnValue
        }

        resultFutures.transpose().getOrThrow()
        println("Cash issued to buyer")

        // The CP sale transaction comes with a prospectus PDF, which will tag along for the ride in an
        // attachment. Make sure we have the transaction prospectus attachment loaded into our store.
        //
        // This can also be done via an HTTP upload, but here we short-circuit and do it from code.
        if (!rpc.attachmentExists(SellerFlow.PROSPECTUS_HASH)) {
            javaClass.classLoader.getResourceAsStream("bank-of-london-cp.jar").use {
                val id = rpc.uploadAttachment(it)
                check(SellerFlow.PROSPECTUS_HASH == id)
            }
        }

        // The line below blocks and waits for the future to resolve.
        val stx = rpc.startFlow(::CommercialPaperIssueFlow, amount, ref, seller, notaryNode.notaryIdentity).returnValue.getOrThrow()
        println("Commercial paper issued to seller")
    }

    fun runSeller(amount: Amount<Currency> = 1000.0.DOLLARS, buyerName: X500Name) {
        val otherParty = rpc.partyFromX500Name(buyerName) ?: throw IllegalStateException("Don't know $buyerName")
        // The seller will sell some commercial paper to the buyer, who will pay with (self issued) cash.
        //
        // The CP sale transaction comes with a prospectus PDF, which will tag along for the ride in an
        // attachment. Make sure we have the transaction prospectus attachment loaded into our store.
        //
        // This can also be done via an HTTP upload, but here we short-circuit and do it from code.
        if (!rpc.attachmentExists(SellerFlow.PROSPECTUS_HASH)) {
            javaClass.classLoader.getResourceAsStream("bank-of-london-cp.jar").use {
                val id = rpc.uploadAttachment(it)
                check(SellerFlow.PROSPECTUS_HASH == id)
            }
        }

        // The line below blocks and waits for the future to resolve.
        val stx = rpc.startFlow(::SellerFlow, otherParty, amount).returnValue.getOrThrow()
        println("Sale completed - we have a happy customer!\n\nFinal transaction is:\n\n${Emoji.renderIfSupported(stx.tx)}")
    }
}
