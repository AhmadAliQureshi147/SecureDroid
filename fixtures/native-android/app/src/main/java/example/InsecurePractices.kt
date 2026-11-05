package example

import android.content.Intent
import dalvik.system.DexClassLoader
import javax.net.ssl.SSLContext

class InsecurePractices {
    fun run(intent: Intent) {
        SSLContext.getInstance("TLSv1")
        Intent.parseUri(intent.dataString, Intent.URI_ALLOW_UNSAFE)
        DexClassLoader(intent.getStringExtra("dex"), null, null, javaClass.classLoader)
        android.webkit.WebView(null).settings.setSafeBrowsingEnabled(false)
        createPackageContext("com.other.app", CONTEXT_INCLUDE_CODE or CONTEXT_IGNORE_SECURITY)
        System.load(intent.getStringExtra("native"))
        java.security.SecureRandom().setSeed(7)
        okhttp3.logging.HttpLoggingInterceptor().setLevel(okhttp3.logging.HttpLoggingInterceptor.Level.BODY)
        javax.crypto.Cipher.getInstance("AES")
    }
}
