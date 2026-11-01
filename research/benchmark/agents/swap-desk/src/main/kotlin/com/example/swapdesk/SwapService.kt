package com.example.swapdesk

import java.math.BigDecimal
import java.math.RoundingMode
import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.Serializable
import org.stellar.sdk.Asset
import org.stellar.sdk.KeyPair
import org.stellar.sdk.Network
import org.stellar.sdk.PathPaymentStrictSendOperation
import org.stellar.sdk.PaymentOperation
import org.stellar.sdk.Server
import org.stellar.sdk.Transaction
import org.stellar.sdk.TransactionBuilder

@Serializable
data class SwapRequest(
    val sendCode: String,
    val sendIssuer: String? = null,
    val sendAmount: String,
    val destCode: String,
    val destIssuer: String? = null,
    val expectedOut: String,
    val slippageBps: Int = 50,
)

@Serializable
data class WithdrawRequest(val code: String, val issuer: String? = null, val amount: String, val destination: String)

class Balances {
    private val byUser = ConcurrentHashMap<String, MutableMap<Pair<String, String?>, BigDecimal>>()

    fun of(userId: String): Map<String, String> =
        byUser[userId].orEmpty().mapKeys { (k, _) -> k.first + (k.second?.let { ":$it" } ?: "") }
            .mapValues { it.value.toPlainString() }

    @Synchronized
    fun debit(userId: String, asset: Pair<String, String?>, amount: BigDecimal) {
        val wallet = byUser.getOrPut(userId) { mutableMapOf() }
        val current = wallet[asset] ?: BigDecimal.ZERO
        require(current >= amount) { "insufficient ${asset.first} balance" }
        wallet[asset] = current - amount
    }

    @Synchronized
    fun credit(userId: String, asset: Pair<String, String?>, amount: BigDecimal) {
        val wallet = byUser.getOrPut(userId) { mutableMapOf() }
        wallet[asset] = (wallet[asset] ?: BigDecimal.ZERO) + amount
    }
}

class SwapService(private val server: Server, private val omnibus: KeyPair, val balances: Balances) {

    private fun amount(raw: String): BigDecimal {
        val value = BigDecimal(raw)
        require(value.signum() > 0 && value.scale() <= 7) { "invalid amount $raw" }
        return value
    }

    private fun submit(addOps: TransactionBuilder.() -> Unit): String {
        val account = server.accounts().account(omnibus.accountId)
        val builder = TransactionBuilder(account, Network.PUBLIC)
            .setBaseFee(Transaction.MIN_BASE_FEE * 5)
            .setTimeout(60)
        builder.addOps()
        val tx = builder.build()
        tx.sign(omnibus)
        val response = server.submitTransaction(tx)
        return response.hash
    }

    fun swap(userId: String, req: SwapRequest): Map<String, String> {
        val sendKey = SupportedAssets.require(req.sendCode, req.sendIssuer)
        val destKey = SupportedAssets.require(req.destCode, req.destIssuer)
        val sendAmount = amount(req.sendAmount)
        val expectedOut = amount(req.expectedOut)
        val destMin = expectedOut.multiply(BigDecimal.ONE - BigDecimal(req.slippageBps).movePointLeft(4))
            .setScale(7, RoundingMode.DOWN)

        balances.debit(userId, sendKey, sendAmount)
        val hash = submit {
            addOperation(
                PathPaymentStrictSendOperation.Builder(
                    SupportedAssets.toAsset(sendKey), sendAmount.toPlainString(),
                    omnibus.accountId, SupportedAssets.toAsset(destKey), destMin.max(BigDecimal("0.0000001")).toPlainString(),
                ).build()
            )
        }
        balances.credit(userId, destKey, expectedOut)
        return mapOf("tx" to hash, "credited" to expectedOut.toPlainString())
    }

    fun withdraw(userId: String, req: WithdrawRequest): Map<String, String> {
        val key = SupportedAssets.require(req.code, req.issuer)
        val value = amount(req.amount)
        balances.debit(userId, key, value)
        val hash = submit {
            addOperation(PaymentOperation.Builder(req.destination, SupportedAssets.toAsset(key), value.toPlainString()).build())
        }
        return mapOf("tx" to hash)
    }
}

class Treasury(private val server: Server, seed: String, private val omnibusAccount: String) {
    private val signer = KeyPair.fromSecretSeed(seed)
    private val usdc: Asset = SupportedAssets.toAsset(SupportedAssets.require("USDC", "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"))

    fun topUpOmnibus(amount: String): String {
        val value = BigDecimal(amount)
        require(value.signum() > 0 && value <= BigDecimal("50000")) { "rebalance amount out of range" }
        val account = server.accounts().account(signer.accountId)
        val tx = TransactionBuilder(account, Network.PUBLIC)
            .addOperation(PaymentOperation.Builder(omnibusAccount, usdc, value.toPlainString()).build())
            .setBaseFee(Transaction.MIN_BASE_FEE * 2)
            .setTimeout(120)
            .build()
        tx.sign(signer)
        return server.submitTransaction(tx).hash
    }
}
