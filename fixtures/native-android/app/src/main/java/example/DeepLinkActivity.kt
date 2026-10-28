package example

import android.app.Activity
import android.os.Bundle

class DeepLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val to = intent?.data?.getQueryParameter("to")
        val amount = intent?.data?.getQueryParameter("amount")
        transfer(to, amount)
    }

    private fun transfer(to: String?, amount: String?) {
        // Privileged operation reached from the deep link.
    }
}
