package com.fluxlock.app

import android.app.DownloadManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.content.FileProvider
import androidx.fragment.app.FragmentActivity
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * AppUpdater — Exposed to WebView as `window.AndroidUpdater`.
 *
 * Mise à jour in-app via les releases GitHub :
 *   1. checkForUpdate(callbackId) — interroge l'API GitHub, compare avec la version installée
 *   2. startDownload(url, version, sha256) — télécharge l'APK via DownloadManager (en arrière-plan,
 *      survit à la fermeture de l'activité)
 *   3. getDownloadStatus() — état courant (idle / downloading / ready / failed), APK vérifié
 *   4. installUpdate() — ouvre l'installeur système sur l'APK vérifié (action explicite de l'utilisateur)
 *
 * Avant d'être déclaré "ready", l'APK doit avoir : le même package, un versionCode supérieur,
 * la même signature que l'app installée, et (si fourni par GitHub) le bon SHA-256.
 */
class AppUpdater(
    private val activity: FragmentActivity,
    private val webView: WebView
) {
    companion object {
        private const val TAG = "FluXlock.Update"
        private const val GITHUB_REPO = "Tiemtore-dev/fluxlock-releases"
        private const val LATEST_RELEASE_URL = "https://api.github.com/repos/$GITHUB_REPO/releases/latest"
        private const val PREFS = "fluxlock_updater"
        private const val KEY_DOWNLOAD_ID = "download_id"
        private const val KEY_VERSION = "version"
        private const val KEY_FILE = "file_name"
        private const val KEY_SHA256 = "sha256"
    }

    private val prefs = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val downloadManager =
        activity.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager

    // Résultat de la vérification de l'APK, mémorisé pour ne pas re-hasher à chaque poll.
    @Volatile private var verifiedDownloadId = -1L
    @Volatile private var verifyError: String? = null

    init {
        cleanupObsoleteDownload()
    }

    // ═══════════════════════════════════════════════════════════
    // 1. Vérification de la dernière release
    // ═══════════════════════════════════════════════════════════

    @JavascriptInterface
    fun checkForUpdate(callbackId: String) {
        Thread {
            val result = JSONObject()
            try {
                val current = currentVersionName()
                result.put("currentVersion", current)

                val conn = URL(LATEST_RELEASE_URL).openConnection() as HttpURLConnection
                try {
                    conn.connectTimeout = 10_000
                    conn.readTimeout = 10_000
                    conn.setRequestProperty("Accept", "application/vnd.github+json")
                    conn.setRequestProperty("User-Agent", "FluXlock-Android/$current")
                    if (conn.responseCode != 200) {
                        throw IllegalStateException("GitHub a répondu ${conn.responseCode}")
                    }
                    val release = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
                    val latest = release.getString("tag_name").trimStart('v', 'V')
                    val asset = pickApkAsset(release)

                    result.put("latestVersion", latest)
                    result.put("notes", release.optString("body", ""))
                    if (asset != null && isNewer(current, latest)) {
                        result.put("available", true)
                        result.put("url", asset.getString("browser_download_url"))
                        result.put("size", asset.optLong("size", 0))
                        result.put("sha256", asset.optString("digest", "").removePrefix("sha256:"))
                    } else {
                        // Pas d'APK attaché à la release = rien à proposer sur Android.
                        result.put("available", false)
                    }
                } finally {
                    conn.disconnect()
                }
            } catch (e: Exception) {
                Log.w(TAG, "Vérification impossible: ${e.message}")
                result.put("available", false)
                result.put("error", e.message ?: "Erreur inconnue")
            }
            resolve(callbackId, result.toString())
        }.start()
    }

    /** Préfère l'APK correspondant à l'ABI de l'appareil, sinon le premier .apk de la release. */
    private fun pickApkAsset(release: JSONObject): JSONObject? {
        val assets = release.optJSONArray("assets") ?: return null
        val apks = (0 until assets.length())
            .map { assets.getJSONObject(it) }
            .filter { it.optString("name").endsWith(".apk", ignoreCase = true) }
        return apks.firstOrNull { a -> Build.SUPPORTED_ABIS.any { a.optString("name").contains(it) } }
            ?: apks.firstOrNull { it.optString("name").contains("universal", ignoreCase = true) }
            ?: apks.firstOrNull()
    }

    // ═══════════════════════════════════════════════════════════
    // 2. Téléchargement en arrière-plan
    // ═══════════════════════════════════════════════════════════

    @JavascriptInterface
    fun startDownload(url: String, version: String, sha256: String): String {
        val uri = Uri.parse(url)
        val host = uri.host ?: return "error:URL invalide"
        val trusted = host == "github.com" || host.endsWith(".github.com") ||
            host.endsWith(".githubusercontent.com")
        if (uri.scheme != "https" || !trusted) return "error:Source non autorisée"

        discardCurrentDownload()

        val fileName = "FluXlock-${version.replace(Regex("[^0-9A-Za-z.\\-]"), "_")}.apk"
        val request = DownloadManager.Request(uri)
            .setTitle("FluXlock $version")
            .setDescription("Téléchargement de la mise à jour")
            .setMimeType("application/vnd.android.package-archive")
            .addRequestHeader("User-Agent", "FluXlock-Android/${currentVersionName()}")
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE)
            .setDestinationInExternalFilesDir(activity, Environment.DIRECTORY_DOWNLOADS, fileName)

        val id = downloadManager.enqueue(request)
        prefs.edit()
            .putLong(KEY_DOWNLOAD_ID, id)
            .putString(KEY_VERSION, version)
            .putString(KEY_FILE, fileName)
            .putString(KEY_SHA256, sha256)
            .apply()
        verifiedDownloadId = -1L
        verifyError = null
        return "ok"
    }

    @JavascriptInterface
    fun getDownloadStatus(): String {
        val out = JSONObject().put("state", "idle")
        val id = prefs.getLong(KEY_DOWNLOAD_ID, -1L)
        if (id < 0) return out.toString()
        out.put("version", prefs.getString(KEY_VERSION, ""))

        val cursor = downloadManager.query(DownloadManager.Query().setFilterById(id))
        cursor.use { c ->
            if (!c.moveToFirst()) {
                // Téléchargement annulé par l'utilisateur depuis le système.
                prefs.edit().remove(KEY_DOWNLOAD_ID).apply()
                return out.toString()
            }
            val status = c.getInt(c.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS))
            val downloaded = c.getLong(c.getColumnIndexOrThrow(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR))
            val total = c.getLong(c.getColumnIndexOrThrow(DownloadManager.COLUMN_TOTAL_SIZE_BYTES))
            out.put("downloaded", downloaded).put("total", total)

            when (status) {
                DownloadManager.STATUS_SUCCESSFUL -> {
                    val error = verifyDownloadedApk(id)
                    if (error == null) out.put("state", "ready")
                    else out.put("state", "failed").put("error", error)
                }
                DownloadManager.STATUS_FAILED -> {
                    val reason = c.getInt(c.getColumnIndexOrThrow(DownloadManager.COLUMN_REASON))
                    out.put("state", "failed").put("error", "Échec du téléchargement (code $reason)")
                }
                else -> out.put("state", "downloading")
            }
        }
        return out.toString()
    }

    // ═══════════════════════════════════════════════════════════
    // 3. Installation (déclenchée par l'utilisateur)
    // ═══════════════════════════════════════════════════════════

    /** Retourne "ok", "needs_permission" ou "error:<message>". */
    @JavascriptInterface
    fun installUpdate(): String {
        val id = prefs.getLong(KEY_DOWNLOAD_ID, -1L)
        val file = downloadedFile() ?: return "error:Aucune mise à jour téléchargée"
        if (id < 0 || verifyDownloadedApk(id) != null) return "error:APK invalide"

        if (!activity.packageManager.canRequestPackageInstalls()) {
            activity.runOnUiThread {
                activity.startActivity(
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${activity.packageName}"))
                )
            }
            return "needs_permission"
        }

        return try {
            val apkUri = FileProvider.getUriForFile(activity, "${activity.packageName}.fileprovider", file)
            val intent = Intent(Intent.ACTION_VIEW)
                .setDataAndType(apkUri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            activity.runOnUiThread { activity.startActivity(intent) }
            "ok"
        } catch (e: Exception) {
            Log.e(TAG, "Lancement de l'installeur impossible", e)
            "error:${e.message}"
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Vérification de l'APK
    // ═══════════════════════════════════════════════════════════

    /** Retourne null si l'APK est digne de confiance, sinon un message d'erreur. */
    private fun verifyDownloadedApk(id: Long): String? {
        if (verifiedDownloadId == id) return verifyError
        val error = try { doVerify() } catch (e: Exception) { "Vérification impossible: ${e.message}" }
        if (error != null) {
            Log.w(TAG, "APK rejeté: $error")
            downloadedFile()?.delete()
        }
        verifiedDownloadId = id
        verifyError = error
        return error
    }

    @Suppress("DEPRECATION")
    private fun doVerify(): String? {
        val file = downloadedFile() ?: return "Fichier introuvable"

        val expected = prefs.getString(KEY_SHA256, "") ?: ""
        if (expected.isNotEmpty()) {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { s ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = s.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                }
            }
            val actual = digest.digest().joinToString("") { "%02x".format(it) }
            if (!actual.equals(expected, ignoreCase = true)) return "Empreinte SHA-256 incorrecte"
        }

        val pm = activity.packageManager
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
                    else PackageManager.GET_SIGNATURES
        val archive = pm.getPackageArchiveInfo(file.absolutePath, flags) ?: return "APK illisible"
        val installed = pm.getPackageInfo(activity.packageName, flags)

        if (archive.packageName != activity.packageName) return "Package différent"
        if (versionCodeOf(archive) <= versionCodeOf(installed)) return "Version non supérieure"
        if (signersOf(archive) != signersOf(installed)) return "Signature différente de l'application installée"
        return null
    }

    @Suppress("DEPRECATION")
    private fun versionCodeOf(info: android.content.pm.PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()

    @Suppress("DEPRECATION")
    private fun signersOf(info: android.content.pm.PackageInfo): Set<String> {
        val sigs = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        return sigs?.map { it.toCharsString() }?.toSet() ?: emptySet()
    }

    // ═══════════════════════════════════════════════════════════
    // Utilitaires
    // ═══════════════════════════════════════════════════════════

    private fun currentVersionName(): String =
        activity.packageManager.getPackageInfo(activity.packageName, 0).versionName ?: "0"

    private fun downloadedFile(): File? {
        val name = prefs.getString(KEY_FILE, null) ?: return null
        val file = File(activity.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), name)
        return if (file.exists()) file else null
    }

    private fun discardCurrentDownload() {
        val id = prefs.getLong(KEY_DOWNLOAD_ID, -1L)
        if (id >= 0) downloadManager.remove(id)
        downloadedFile()?.delete()
        prefs.edit().clear().apply()
    }

    /** Une fois la mise à jour installée (version courante >= version téléchargée), on libère l'APK. */
    private fun cleanupObsoleteDownload() {
        val version = prefs.getString(KEY_VERSION, null) ?: return
        if (!isNewer(currentVersionName(), version)) discardCurrentDownload()
    }

    /** True si `latest` est strictement supérieure à `current` (comparaison numérique x.y.z). */
    private fun isNewer(current: String, latest: String): Boolean {
        fun parts(v: String) = v.substringBefore('-').substringBefore('+')
            .split('.').map { it.toIntOrNull() ?: 0 }
        val a = parts(current)
        val b = parts(latest)
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (y != x) return y > x
        }
        return false
    }

    private fun resolve(callbackId: String, payload: String) {
        val js = "window.__updaterResolve && window.__updaterResolve(" +
            "${JSONObject.quote(callbackId)}, ${JSONObject.quote(payload)})"
        activity.runOnUiThread { webView.evaluateJavascript(js, null) }
    }
}
