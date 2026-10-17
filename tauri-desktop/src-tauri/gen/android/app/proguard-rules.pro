# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# ═══════════════════════════════════════════════════════
# FluXlock — BiometricBridge (JS ↔ Kotlin via WebView)
#
# R8/ProGuard must NOT strip or rename @JavascriptInterface
# methods — they are called at runtime from WebView JS.
# ═══════════════════════════════════════════════════════
-keep class com.fluxlock.app.BiometricBridge {
    @android.webkit.JavascriptInterface public *;
    public *;
}

# AppUpdater (window.AndroidUpdater) — même contrainte que BiometricBridge
-keep class com.fluxlock.app.AppUpdater {
    @android.webkit.JavascriptInterface public *;
    public *;
}

# Keep BiometricPrompt callbacks (invoked via reflection by AndroidX)
-keep class androidx.biometric.** { *; }

# Keep Android Keystore + crypto classes used by BiometricBridge
-keep class android.security.keystore.** { *; }
-keep class javax.crypto.** { *; }

# Keep MainActivity (registers BiometricBridge)
-keep class com.fluxlock.app.MainActivity {
    public *;
}

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile