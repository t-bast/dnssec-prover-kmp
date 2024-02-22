import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.bundling.Jar
import org.gradle.kotlin.dsl.`maven-publish`

plugins {
    `maven-publish`
    signing
}

publishing {
    // Configure all publications
    publications.withType<MavenPublication> {
        // Stub javadoc.jar artifact
        artifact(tasks.register("${name}JavadocJar", Jar::class) {
            archiveClassifier.set("javadoc")
            archiveAppendix.set(this@withType.name)
        })

        // Provide artifacts information required by Maven Central
        pom {
            name.set("Kotlin Multiplatform DNSSEC Prover")
            description.set("Kotlin library to create transferable DNSSEC proofs")
            url.set("https://github.com/t-bast/dnssec-prover-kmp")

            licenses {
                license {
                    name.set("Apache 2.0")
                    url.set("https://opensource.org/license/apache-2-0")
                }
            }
            developers {
                developer {
                    id.set("ACINQ")
                    name.set("ACINQ")
                    organization.set("ACINQ")
                    organizationUrl.set("https://acinq.co")
                }
            }
            scm {
                url.set("https://github.com/t-bast/dnssec-prover-kmp")
            }
        }
    }
}

signing {
    if (project.hasProperty("signing.gnupg.keyName")) {
        useGpgCmd()
        sign(publishing.publications)
    }
}
