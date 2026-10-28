package example

import android.database.sqlite.SQLiteDatabase

fun lookup(db: SQLiteDatabase, name: String) {
    db.rawQuery("select * from users where name = '" + name + "'", null)
}
