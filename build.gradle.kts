import org.gradle.kotlin.dsl.java
import java.io.ByteArrayOutputStream
import java.io.File

plugins {
    application
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

repositories { mavenCentral() }

dependencies {
    implementation("com.formdev:flatlaf:3.4.1")
    implementation("com.formdev:flatlaf-extras:3.4.1")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("de.mkammerer:argon2-jvm:2.11")
}

application {
    mainClass.set("vault.PasswordVaultFX")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21)) // JDK with jpackage
    }
}

/**
 * Make the Shadow jar name predictable:
 *   build/libs/MyVault-all.jar
 * (no version in the filename)
 */
tasks.shadowJar {
    archiveBaseName.set("MyVault")
    archiveClassifier.set("")
    archiveVersion.set("") // remove version from filename
}

/**
 * Windows EXE via jpackage
 * Requires: JDK 17+ on PATH (or set Gradle JVM in IntelliJ to JDK 17/21)
 * Icon file at: <project>/icons/app-icon.ico
 */

tasks.register<Exec>("jpackageWin") {
    dependsOn(tasks.shadowJar)

    val appName = "MyVault"
    val appVer = "1.0.0"

    // Resolve jpackage from the configured JDK 21 toolchain (Windows)
    val launcher = javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(21))
    }.get()
    val javaHome = launcher.metadata.installationPath.asFile
    val jpackageExe = File(javaHome, "bin/jpackage.exe")

    val inputDir = project.layout.buildDirectory.dir("libs").get().asFile
    val mainJar = "MyVault.jar"  // matches shadowJar naming we set
    val iconFile = project.layout.projectDirectory.file("icons/app-icon.ico").asFile

    doFirst {
        println("Using Java home: ${javaHome.absolutePath}")
        println("Using jpackage  : ${jpackageExe.absolutePath}")

        if (!jpackageExe.exists()) throw GradleException("jpackage not found at: ${jpackageExe}")
        if (!iconFile.exists()) throw GradleException("Icon not found at: ${iconFile}")
        if (!File(
                inputDir,
                mainJar
            ).exists()
        ) throw GradleException("Missing $mainJar in ${inputDir}. Run :shadowJar and confirm name.")

        // Probe supported types to prove we're calling the right jpackage
        val out = ByteArrayOutputStream()
        project.exec {
            executable = jpackageExe.absolutePath
            args("--help")
            standardOutput = out
            errorOutput = out
            isIgnoreExitValue = true
        }
        val help = out.toString()
        println("---- jpackage --help (trimmed) ----")
        println(help.lines().take(20).joinToString("\n"))
        println("-----------------------------------")

        if (!help.contains("exe") || !help.contains("Valid values")) {
            throw GradleException("This jpackage doesn't list 'exe' as a supported type.\nHelp output:\n$help")
        }
    }

    executable = jpackageExe.absolutePath
    args(
        "--type", "exe",
        "--name", appName,
        "--app-version", appVer,
        "--input", inputDir.absolutePath,
        "--main-jar", mainJar,
        "--main-class", "vault.PasswordVaultFX",
        "--icon", iconFile.absolutePath,
        "--win-menu",
        "--win-shortcut",
        "--vendor", "MyVault",
        "--dest", project.layout.projectDirectory.dir("dist").asFile.absolutePath
    )
}


tasks.jar {
    manifest {
        attributes["Main-Class"] = "vault.PasswordVaultFX"
    }
}
