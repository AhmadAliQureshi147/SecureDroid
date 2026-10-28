plugins {
    id("com.android.application")
}

android {
    buildTypes {
        debug {
            isDebuggable = true
        }
        release {
            isDebuggable = false
        }
    }
}
