package com.redteam.probe;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;

public class ProbeNotificationListener extends NotificationListenerService {
    private static final String TAG = "RedTeamProbe";

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        String pkg = sbn.getPackageName();
        String title = "";
        String text = "";
        try {
            android.os.Bundle extras = sbn.getNotification().extras;
            title = extras.getString("android.title", "");
            CharSequence t = extras.getCharSequence("android.text");
            text = t != null ? t.toString() : "";
        } catch (Exception e) {}
        Log.i(TAG, "NOTIF: [" + pkg + "] " + title + " → " + text);
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
    }

    @Override
    public void onListenerConnected() {
        Log.i(TAG, "NOTIFICATION LISTENER CONNECTED - can read all notifications");
    }
}
