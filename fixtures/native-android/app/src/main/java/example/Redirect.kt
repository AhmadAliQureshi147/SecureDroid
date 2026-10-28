package example

import android.app.Activity
import android.content.Intent

class RedirectActivity : Activity() {
    fun openNext() {
        val next = intent.getParcelableExtra<Intent>("next")
        startActivity(next)
    }
}
