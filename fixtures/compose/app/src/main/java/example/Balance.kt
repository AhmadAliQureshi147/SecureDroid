package example

import android.util.Log
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable

@Composable
fun Balance(token: String) {
    Log.d("Balance", "token=$token")
    Text(text = token)
}
