package example

import android.webkit.SslErrorHandler
import android.webkit.WebView
import java.io.File
import java.io.ObjectInputStream
import java.util.zip.ZipEntry
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Page {
    fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: android.net.http.SslError) {
        handler.proceed()
    }

    fun mixed(settings: android.webkit.WebSettings) {
        settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
    }

    fun debug() {
        WebView.setWebContentsDebuggingEnabled(true)
    }

    fun script(webView: WebView, payload: String) {
        webView.loadUrl("javascript:" + payload)
    }
}

fun key(): SecretKeySpec {
    return SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
}

fun weak(): Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")

fun iv(bytes: ByteArray): IvParameterSpec {
    val random = java.util.Random()
    random.nextBytes(bytes)
    return IvParameterSpec(bytes)
}

fun prefs(context: android.content.Context, token: String) {
    context.getSharedPreferences("app", 0).edit().putString("auth_token", token).apply()
}

fun external(password: String) {
    val dir = android.os.Environment.getExternalStorageDirectory()
    File(dir, "notes.txt").writeText(password)
}

fun copyToken(clipboard: android.content.ClipboardManager, token: String) {
    clipboard.setPrimaryClip(android.content.ClipData.newPlainText("token", token))
}

fun unzip(entry: ZipEntry, dest: File) {
    val out = File(dest, entry.name)
    out.writeBytes(byteArrayOf())
}

fun openPath(intent: android.content.Intent, root: File): File {
    return File(root, intent.getStringExtra("path"))
}

fun read(input: ObjectInputStream): Any = input.readObject()
