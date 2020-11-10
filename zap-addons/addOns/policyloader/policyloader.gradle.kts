version = "1"
description = "Rules policy loader"

zapAddOn {
    addOnName.set("Rules policy loader")
    zapVersion.set("2.9.0")

    manifest {
        author.set("Group17")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}
