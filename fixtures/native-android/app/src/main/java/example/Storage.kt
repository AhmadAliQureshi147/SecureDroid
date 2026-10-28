package example

import android.content.Context
import android.util.Log

fun save(context: Context, password: String) {
    context.openFileOutput("notes", MODE_WORLD_READABLE).write(password.toByteArray())
    java.io.File("notes").setReadable(true, false)
    Log.d("auth", "password=$password")
}
