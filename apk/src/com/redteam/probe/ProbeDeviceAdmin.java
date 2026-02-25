package com.redteam.probe;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class ProbeDeviceAdmin extends DeviceAdminReceiver {
    private static final String TAG = "RedTeamProbe";

    @Override
    public void onEnabled(Context context, Intent intent) {
        Log.i(TAG, "DEVICE ADMIN ENABLED - we now have MDM capabilities");
    }

    @Override
    public void onDisabled(Context context, Intent intent) {
        Log.i(TAG, "DEVICE ADMIN DISABLED");
    }
}
