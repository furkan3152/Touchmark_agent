package com.example.swapdesk

import org.stellar.sdk.Asset

object SupportedAssets {
    private const val CIRCLE = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
    private const val AQUA = "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"

    private val supported: Set<Pair<String, String?>> = setOf(
        "XLM" to null,
        "USDC" to CIRCLE,
        "EURC" to "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2",
        "AQUA" to AQUA,
    )

    fun require(code: String, issuer: String?): Pair<String, String?> {
        val key = code.uppercase() to issuer?.takeIf { code.uppercase() != "XLM" }
        if (key !in supported) {
            throw IllegalArgumentException("unsupported asset $code:${issuer ?: "native"}")
        }
        return key
    }

    fun toAsset(key: Pair<String, String?>): Asset =
        if (key.second == null) Asset.createNativeAsset() else Asset.createNonNativeAsset(key.first, key.second)
}
