package com.fluxlock.app

import android.Manifest
import android.content.ContentValues
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import android.webkit.JavascriptInterface
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.io.File

/**
 * PublicStorage — Exposed to WebView as `window.AndroidStorage`.
 *
 * Saves files (backups, CSV exports) into the public `Documents/FluXlock/` folder so they
 * survive an uninstall of the app and are reachable from the system file manager.
 *
 *   - Android 10+ (API 29+): MediaStore, no permission needed.
 *   - Android 7-9: direct write, needs WRITE_EXTERNAL_STORAGE (requested at first use).
 *
 * All methods return "ok:<human readable location>", "needs_permission" or "error:<message>".
 */
class PublicStorage(private val activity: FragmentActivity) {
    companion object {
        private const val TAG = "FluXlock.Storage"
        private const val FOLDER = "FluXlock"
    }

    @JavascriptInterface
    fun saveText(content: String, fileName: String, mimeType: String): String =
        save(fileName, mimeType) { out -> out.write(content.toByteArray(Charsets.UTF_8)) }

    @JavascriptInterface
    fun saveFile(sourcePath: String, fileName: String, mimeType: String): String {
        val src = File(sourcePath)
        if (!src.isFile) return "error:Fichier source introuvable"
        return save(fileName, mimeType) { out -> src.inputStream().use { it.copyTo(out) } }
    }

    private fun save(fileName: String, mimeType: String, writer: (java.io.OutputStream) -> Unit): String {
        val safeName = fileName.replace(Regex("[^A-Za-z0-9._ ()-]"), "_").trimStart('.')
        if (safeName.isEmpty()) return "error:Nom de fichier invalide"
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) saveViaMediaStore(safeName, mimeType, writer)
            else saveLegacy(safeName, writer)
        } catch (e: Exception) {
            Log.e(TAG, "save failed", e)
            "error:${e.message ?: "écriture impossible"}"
        }
    }

    private fun saveViaMediaStore(name: String, mime: String, writer: (java.io.OutputStream) -> Unit): String {
        val resolver = activity.contentResolver
        val relativePath = "${Environment.DIRECTORY_DOCUMENTS}/$FOLDER"
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val collection = MediaStore.Files.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        val uri = resolver.insert(collection, values) ?: return "error:Création du fichier impossible"
        try {
            val out = resolver.openOutputStream(uri) ?: throw IllegalStateException("Flux de sortie indisponible")
            out.use(writer)
            resolver.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
        } catch (e: Exception) {
            resolver.delete(uri, null, null)
            throw e
        }
        // MediaStore may rename on conflict ("name (1).ext"): report the real name.
        val finalName = resolver.query(uri, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)
            ?.use { if (it.moveToFirst()) it.getString(0) else null } ?: name
        return "ok:$relativePath/$finalName"
    }

    private fun saveLegacy(name: String, writer: (java.io.OutputStream) -> Unit): String {
        val granted = ContextCompat.checkSelfPermission(
            activity, Manifest.permission.WRITE_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE), 4242)
            return "needs_permission"
        }
        @Suppress("DEPRECATION")
        val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), FOLDER)
        if (!dir.exists() && !dir.mkdirs()) return "error:Création du dossier impossible"
        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val ext = if (dot > 0) name.substring(dot) else ""
        var target = File(dir, name)
        var n = 1
        while (target.exists()) target = File(dir, "$stem ($n)$ext").also { n++ }
        target.outputStream().use(writer)
        return "ok:${Environment.DIRECTORY_DOCUMENTS}/$FOLDER/${target.name}"
    }
}
