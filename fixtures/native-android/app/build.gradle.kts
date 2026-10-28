plugins {
    id("com.android.application")
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
