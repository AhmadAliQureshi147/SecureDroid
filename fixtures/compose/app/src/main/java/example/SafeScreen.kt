package example

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember

@Composable
fun SafeScreen() {
    val count = remember { mutableStateOf(0) }
    Text(text = count.value.toString())
}
