plugins {
    kotlin("jvm") version "2.0.21"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Used only by Coroutines.kt, which is optional — delete that file and this
    // project has no dependencies beyond kotlin-stdlib.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    testImplementation(kotlin("test"))
}

// No jvmToolchain() on purpose: it would make Gradle provision a second JDK.
// The library half uses nothing outside java.net + javax.crypto + kotlin-stdlib,
// so an Android module recompiles these sources at its own target level anyway.

application {
    mainClass.set("org.tgproxycheck.MainKt")
}

tasks.test {
    useJUnitPlatform()
}
