plugins {
    kotlin("jvm") version "2.0.21"
    `maven-publish`
}

group = "io.peakauth"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Tests
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(21)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = "io.peakauth"
            artifactId = "peak-auth-kotlin"
            version = "1.0.0"
        }
    }
}
