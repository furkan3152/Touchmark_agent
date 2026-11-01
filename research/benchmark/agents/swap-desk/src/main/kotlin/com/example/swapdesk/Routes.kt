package com.example.swapdesk

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.principal
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable

@Serializable
data class RebalanceRequest(val amount: String)

fun Application.configureRoutes(service: SwapService, treasury: Treasury) {
    routing {
        authenticate("ops") {
            post("/admin/rebalance") {
                val body = call.receive<RebalanceRequest>()
                call.respond(mapOf("tx" to treasury.topUpOmnibus(body.amount)))
            }
        }
        authenticate("user") {
            get("/users/{userId}/balances") {
                val principal = call.principal<JWTPrincipal>()!!
                if (call.parameters["userId"] != principal.userId) {
                    call.respond(HttpStatusCode.Forbidden)
                    return@get
                }
                call.respond(service.balances.of(principal.userId))
            }
            post("/swap") {
                val principal = call.principal<JWTPrincipal>()!!
                call.respond(service.swap(principal.userId, call.receive<SwapRequest>()))
            }
            post("/users/{userId}/withdraw") {
                call.principal<JWTPrincipal>()!!
                val userId = call.parameters["userId"]!!
                call.respond(service.withdraw(userId, call.receive<WithdrawRequest>()))
            }
        }
    }
}
