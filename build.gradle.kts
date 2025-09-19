import org.gradle.jvm.tasks.Jar
import java.io.File

plugins {
    application
}

group = "com.oogle.vaultpro"
version = "1.1.0"

repositories { mavenCentral() }

dependencies {
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("org.tinylog:tinylog-api:2.6.2")
    implementation("org.tinylog:tinylog-impl:2.6.2")
    implementation("com.formdev:flatlaf:3.4.1")
    implementation("com.formdev:flatlaf-extras:3.4.1")
    implementation("com.formdev:flatlaf-intellij-themes:3.4.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
}

application { mainClass.set("com.oogle.vaultpro.VaultProApp") }

java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

tasks.test { useJUnitPlatform() }

tasks.named<Jar>("jar") {
    manifest { attributes["Main-Class"] = application.mainClass.get() }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

val inputDir = layout.buildDirectory.dir("jpackage/input")
val outputDir = layout.buildDirectory.dir("jpackage")

tasks.register<Copy>("stageJars") {
    dependsOn(tasks.named("jar"))
    from(configurations.runtimeClasspath)
    from(tasks.named<Jar>("jar"))
    into(inputDir)
}

fun jpackageExePath(): String {
    val home = System.getenv("JPACKAGE_HOME") ?: System.getProperty("java.home")
    return File(home, "bin/jpackage.exe").absolutePath
}

fun commonJpackageArgs(
    type: String,
    mainJar: String,
    iconFile: File?,
    input: File,
    dest: File
): MutableList<String> {
    val args = mutableListOf(
        "--type", type,
        "--name", "MyVault",
        "--app-version", project.version.toString(),
        "--vendor", "Oogle",
        "--description", "Local, encrypted password vault",
        "--win-dir-chooser",
        "--win-menu", "--win-menu-group", "MyVault",
        "--dest", dest.absolutePath,
        "--input", input.absolutePath,
        "--main-jar", mainJar,
        "--main-class", application.mainClass.get()
    )
    if (iconFile != null && iconFile.exists()) {
        args += listOf("--icon", iconFile.absolutePath)
    }
    return args
}

tasks.register<Exec>("winExe") {
    group = "distribution"
    description = "Build Windows EXE installer via jpackage"
    dependsOn("stageJars")
    outputs.dir(outputDir)

    doFirst {
        val jpkg = File(jpackageExePath())
        require(jpkg.exists()) {
            "jpackage.exe not found at ${jpkg.absolutePath}. Install a full JDK 17+ and/or set JPACKAGE_HOME."
        }

        val input = inputDir.get().asFile
        val dest = outputDir.get().asFile
        val mainJar = tasks.named<Jar>("jar").get().archiveFileName.get()
        require(File(input, mainJar).exists()) {
            "Main jar not staged: ${File(input, mainJar).absolutePath}. Did 'stageJars' run?"
        }

        val ico = project.layout.projectDirectory.file("icons/app-icon.ico").asFile
        val cmd = mutableListOf(jpkg.absolutePath)
        cmd += commonJpackageArgs("exe", mainJar, ico, input, dest)

        commandLine(cmd)
        println(">> Running jpackage EXE:\n${cmd.joinToString(" ")}")
    }

    doLast {
        val out = outputDir.get().asFile
        println("✅ EXE should be here: ${File(out, "VaultPro-${project.version}.exe").absolutePath}")
    }
}

tasks.register<Exec>("winMsi") {
    group = "distribution"
    description = "Build Windows MSI installer via jpackage (WiX required)"
    dependsOn("stageJars")
    outputs.dir(outputDir)

    doFirst {
        val jpkg = File(jpackageExePath())
        require(jpkg.exists()) {
            "jpackage.exe not found at ${jpkg.absolutePath}. Install a full JDK 17+ and/or set JPACKAGE_HOME."
        }

        try {
            exec { commandLine("where", "candle.exe") }
            exec { commandLine("where", "light.exe") }
        } catch (_: Exception) {
            println("⚠️  WiX Toolset not detected on PATH. Install WiX 3.x and ensure its 'bin' is on PATH.")
        }

        val input = inputDir.get().asFile
        val dest = outputDir.get().asFile
        val mainJar = tasks.named<Jar>("jar").get().archiveFileName.get()
        require(File(input, mainJar).exists()) {
            "Main jar not staged: ${File(input, mainJar).absolutePath}. Did 'stageJars' run?"
        }

        val ico = project.layout.projectDirectory.file("icons/app-icon.ico").asFile
        val cmd = mutableListOf(jpkg.absolutePath)
        cmd += commonJpackageArgs("msi", mainJar, ico, input, dest)

        commandLine(cmd)
        println(">> Running jpackage MSI:\n${cmd.joinToString(" ")}")
    }

    doLast {
        val out = outputDir.get().asFile
        println("✅ MSI should be here: ${File(out, "VaultPro-${project.version}.msi").absolutePath}")
    }
}
