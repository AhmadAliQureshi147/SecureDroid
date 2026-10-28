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
    }
}
