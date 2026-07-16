# Keep the JNI bridge class + native methods (names must match the Rust symbols).
-keep class com.ep2pc.core.NativeBridge { *; }
-keep interface com.ep2pc.core.EP2PCEventCallback { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
