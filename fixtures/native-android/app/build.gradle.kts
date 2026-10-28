plugins {
    id("com.android.application")
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:3.14.9")
}

android {
    buildTypes {
        debug {
            isDebuggable = true
        }
        release {
            isDebuggable = true
            signingConfig = signingConfigs.getByName("release")
        }
    }
    signingConfigs {
        create("release") {
            storePassword = "super-secret-value"
            keyPassword = "super-secret-value"
        }
    }
}
