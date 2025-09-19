
plugins { application }

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

java { toolchain { languageVersion.set(JavaLanguageVersion.of(20)) } }

tasks.test { useJUnitPlatform() }
