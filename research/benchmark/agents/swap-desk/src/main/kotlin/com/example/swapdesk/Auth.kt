package com.example.swapdesk

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt

fun Application.configureAuth(secret: String, issuer: String) {
    val verifier = JWT.require(Algorithm.HMAC256(secret)).withIssuer(issuer).build()
    install(Authentication) {
        jwt("user") {
            verifier(verifier)
            validate { credential ->
                if (credential.payload.subject.isNullOrBlank()) null else JWTPrincipal(credential.payload)
            }
        }
        jwt("ops") {
            verifier(verifier)
            validate { credential ->
                val roles = credential.payload.getClaim("roles").asList(String::class.java).orEmpty()
                if ("ops" in roles) JWTPrincipal(credential.payload) else null
            }
        }
    }
}

val JWTPrincipal.userId: String
    get() = payload.subject
