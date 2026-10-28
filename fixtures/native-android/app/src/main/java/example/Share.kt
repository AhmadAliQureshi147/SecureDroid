package example

import android.app.PendingIntent
import android.content.Context
import android.content.Intent

fun share(context: Context, intent: Intent): PendingIntent {
    return PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)
}
