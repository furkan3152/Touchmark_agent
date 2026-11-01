package com.example.swapdesk

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import org.stellar.sdk.KeyPair
import org.stellar.sdk.Server

fun main() {
    embeddedServer(Netty, port = 8080, module = Application::module).start(wait = true)
}

fun Application.module() {
    val env = System.getenv()
    val server = Server(env["HORIZON_URL"] ?: "https://horizon.stellar.org")
    val omnibus = KeyPair.fromSecretSeed(env.getValue("OMNIBUS_SEED"))
    val service = SwapService(server, omnibus, Balances())

    install(ContentNegotiation) { json() }
    configureAuth(env.getValue("JWT_SECRET"), env["JWT_ISSUER"] ?: "swap-desk")
    configureRoutes(service, Treasury(server, env.getValue("TREASURY_SEED"), omnibus.accountId))
}
