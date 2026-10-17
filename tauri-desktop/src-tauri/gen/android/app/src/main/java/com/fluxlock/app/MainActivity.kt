package com.fluxlock.app

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Bundle
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  private var multicastLock: WifiManager.MulticastLock? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    acquireMulticastLock()
  }

  @SuppressLint("JavascriptInterface")
  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    webView.addJavascriptInterface(BiometricBridge(this, webView), "AndroidBiometric")
    webView.addJavascriptInterface(AppUpdater(this, webView), "AndroidUpdater")
  }

  /**
   * Acquire a Wi-Fi MulticastLock so the chipset delivers incoming
   * multicast/broadcast UDP packets (mDNS + LAN beacon discovery).
   * Without this, Android power management silently drops them.
   */
  private fun acquireMulticastLock() {
    try {
      val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
      if (wifi != null) {
        multicastLock = wifi.createMulticastLock("fluxlock_discovery").apply {
          setReferenceCounted(false)
          acquire()
        }
        android.util.Log.d("FluXlock", "MulticastLock acquired for LAN discovery")
      }
    } catch (e: Exception) {
      android.util.Log.w("FluXlock", "Failed to acquire MulticastLock: ${e.message}")
    }
  }

  override fun onDestroy() {
    multicastLock?.let {
      if (it.isHeld) {
        it.release()
        android.util.Log.d("FluXlock", "MulticastLock released")
      }
    }
    super.onDestroy()
  }
}
