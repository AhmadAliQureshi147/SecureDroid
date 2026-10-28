package example

import android.app.Activity
import android.webkit.WebView

class WebViewActivity : Activity() {
    fun load(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        webView.settings.allowFileAccess = true
        webView.settings.setAllowUniversalAccessFromFileURLs(true)
        webView.addJavascriptInterface(this, "Android")
        webView.loadUrl(intent.getStringExtra("url"))
    }
}
