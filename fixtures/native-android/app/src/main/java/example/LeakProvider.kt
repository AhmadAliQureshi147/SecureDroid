package example

import android.content.ContentProvider
import android.database.Cursor
import android.net.Uri

class LeakProvider : ContentProvider() {
    override fun query(uri: Uri, projection: Array<String>?, selection: String?, args: Array<String>?, sort: String?): Cursor? {
        return database.rawQuery("select * from accounts", null)
    }

    override fun onCreate(): Boolean = true
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: android.content.ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, args: Array<String>?): Int = 0
    override fun update(uri: Uri, values: android.content.ContentValues?, selection: String?, args: Array<String>?): Int = 0
}
