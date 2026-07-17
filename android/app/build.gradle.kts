import org.gradle.api.tasks.Exec

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.ep2pc"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.ep2pc"
        minSdk = 26          // Android 8.0 — required for modern foreground-service APIs
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            // Ship 64-bit primarily (EP2PC-010 §10.4); add 32-bit/x86 as needed.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Configure your own signingConfig here before release (see repo README).
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildFeatures { compose = true }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-service:2.8.5")
    // QR: generation (ZXing core) + scanning (embedded capture activity).
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}

// --- Rust core cross-compilation via cargo-ndk (EP2PC-010 §10.4) ---
// Requires: `cargo install cargo-ndk` and the Android Rust targets:
//   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
// The ANDROID_NDK_HOME env var must point at your installed NDK.
//
// On CI (Bitrise) the native libs are built in a dedicated script step and this Gradle task
// is skipped with `-PskipRust=true`, so the Gradle daemon never needs cargo on its PATH.
val skipRust = (project.findProperty("skipRust") as String?) == "true"

val cargoNdkBuild by tasks.registering(Exec::class) {
    onlyIf { !skipRust }
    workingDir = file("${rootDir}/../core")
    val jniLibsDir = file("${projectDir}/src/main/jniLibs")
    doFirst { jniLibsDir.mkdirs() }
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "armeabi-v7a",
        "-t", "x86_64",
        "--platform", "26",
        "-o", jniLibsDir.absolutePath,
        "build", "-p", "ep2pc-ffi", "--release"
    )
}

// Build the Rust .so before the Kotlin/Java compile step (unless skipped on CI).
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }
    .configureEach { if (!skipRust) dependsOn(cargoNdkBuild) }
tasks.named("preBuild") { if (!skipRust) dependsOn(cargoNdkBuild) }
