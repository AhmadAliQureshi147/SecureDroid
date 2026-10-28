package example

import android.content.Context
import android.util.Log

fun save(context: Context, password: String) {
    context.openFileOutput("notes", MODE_WORLD_READABLE).write(password.toByteArray())
    Log.d("auth", "password=$password")
}
