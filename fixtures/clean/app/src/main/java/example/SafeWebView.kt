package example

import android.webkit.WebView

class SafeWebView {
    fun load(webView: WebView) {
        webView.settings.javaScriptEnabled = false
        webView.loadUrl("https://example.com/help")
    }
}
