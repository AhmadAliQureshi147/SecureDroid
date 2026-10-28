package example

import android.app.Activity
import android.os.Bundle

class AuthBridgeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val amount = intent?.getStringExtra("amount")
        if (checkCallingPermission("com.example.secure.PERMISSION") != 0) return
        transfer(amount)
    }

    private fun transfer(amount: String?) {
    }
}
