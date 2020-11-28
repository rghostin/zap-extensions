version = "1"
description = "Reportingp proxy"

zapAddOn {
    addOnName.set("Reporing proxy")
    zapVersion.set("2.9.0")

    manifest {
        author.set("Group17")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}
