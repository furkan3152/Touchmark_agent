plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    id("io.ktor.plugin") version "2.3.12"
}

group = "com.example"
version = "0.6.0"

application {
    mainClass.set("com.example.swapdesk.ApplicationKt")
}

repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

dependencies {
    implementation("io.ktor:ktor-server-netty")
    implementation("io.ktor:ktor-server-auth")
    implementation("io.ktor:ktor-server-auth-jwt")
    implementation("io.ktor:ktor-server-content-negotiation")
    implementation("io.ktor:ktor-serialization-kotlinx-json")
    implementation("network.lightsail:stellar-sdk:0.44.0")
    implementation("ch.qos.logback:logback-classic:1.5.8")
}
