package com.redteam.probe;

import android.app.Activity;
import android.os.Bundle;
import android.os.Build;
import android.util.Log;
import android.content.Context;
import android.content.pm.PackageManager;
import java.io.*;
import java.net.*;

/**
 * Main probe activity - dumps environment info and tests capabilities.
 * Triggered: am start -n com.redteam.probe/.ProbeActivity
 * Extras: am start -n com.redteam.probe/.ProbeActivity --es cmd "exec:id"
 */
public class ProbeActivity extends Activity {
    private static final String TAG = "RedTeamProbe";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String cmd = getIntent().getStringExtra("cmd");
        if (cmd != null && cmd.startsWith("exec:")) {
            execCmd(cmd.substring(5));
            return;
        }

        Log.i(TAG, "=== PROBE ENVIRONMENT ===");
        Log.i(TAG, "UID: " + android.os.Process.myUid());
        Log.i(TAG, "PID: " + android.os.Process.myPid());
        Log.i(TAG, "Package: " + getPackageName());

        // SELinux context
        execAndLog("id");
        execAndLog("cat /proc/self/attr/current");
        execAndLog("getenforce");

        // Test file access that shell can't do
        Log.i(TAG, "=== FILE ACCESS TESTS ===");
        testRead("/data/system/packages.xml");
        testRead("/data/misc/wifi/wpa_supplicant.conf");
        testRead("/data/misc/adb/adb_keys");
        testRead("/data/system/locksettings.db");
        testRead("/data/system/users/0.xml");
        testRead("/data/dalvik-cache/");
        testRead("/data/data/com.android.providers.settings/databases/settings.db");
        testRead("/data/data/com.android.providers.contacts/databases/contacts2.db");
        testRead("/proc/1/maps");
        testRead("/sys/fs/selinux/policy");
        testRead("/dev/mobicore-user");

        // Test write access
        Log.i(TAG, "=== WRITE ACCESS TESTS ===");
        testWrite("/data/local/tmp/probe_write_test");
        testWrite("/system/probe_test");
        testWrite("/data/system/probe_test");

        // Network test — can we bind to privileged ports?
        Log.i(TAG, "=== NETWORK TESTS ===");
        testBind(80);
        testBind(443);
        testBind(8080);

        // Try to access content providers as app context
        Log.i(TAG, "=== CONTENT PROVIDER TESTS ===");
        try {
            android.database.Cursor c = getContentResolver().query(
                android.provider.Settings.Secure.CONTENT_URI, null, null, null, null);
            if (c != null) {
                Log.i(TAG, "Settings.Secure: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            Log.i(TAG, "Settings.Secure: " + e.getMessage());
        }

        try {
            android.database.Cursor c = getContentResolver().query(
                android.provider.ContactsContract.Contacts.CONTENT_URI, null, null, null, null);
            if (c != null) {
                Log.i(TAG, "Contacts: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            Log.i(TAG, "Contacts: " + e.getMessage());
        }

        try {
            android.database.Cursor c = getContentResolver().query(
                android.provider.Telephony.Sms.CONTENT_URI, null, null, null, null);
            if (c != null) {
                Log.i(TAG, "SMS: " + c.getCount() + " rows");
                c.close();
            }
        } catch (Exception e) {
            Log.i(TAG, "SMS: " + e.getMessage());
        }

        // Check what our process can see in /proc
        Log.i(TAG, "=== PROC ACCESS ===");
        execAndLog("ls /proc/1/");
        execAndLog("cat /proc/self/status | head -5");
        execAndLog("cat /proc/self/maps | head -5");

        // Check socket access
        Log.i(TAG, "=== SOCKET ACCESS ===");
        testRead("/dev/socket/netd");
        testRead("/dev/socket/zygote");
        testRead("/dev/socket/installd");

        // Try exec as native code
        Log.i(TAG, "=== NATIVE EXEC ===");
        execAndLog("/data/local/tmp/exploit_test --help 2>&1 || echo 'not available'");

        Log.i(TAG, "=== PROBE COMPLETE ===");
        finish();
    }

    private void execCmd(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader er = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            String line;
            while ((line = br.readLine()) != null) Log.i(TAG, "OUT: " + line);
            while ((line = er.readLine()) != null) Log.i(TAG, "ERR: " + line);
            p.waitFor();
            Log.i(TAG, "EXIT: " + p.exitValue());
        } catch (Exception e) {
            Log.e(TAG, "exec failed: " + e.getMessage());
        }
        finish();
    }

    private void execAndLog(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            p.waitFor();
            Log.i(TAG, cmd + " → " + sb.toString().trim());
        } catch (Exception e) {
            Log.i(TAG, cmd + " → ERROR: " + e.getMessage());
        }
    }

    private void testRead(String path) {
        try {
            File f = new File(path);
            if (f.isDirectory()) {
                String[] list = f.list();
                Log.i(TAG, "READ " + path + " → DIR(" + (list != null ? list.length : "null") + " entries)");
            } else {
                FileInputStream fis = new FileInputStream(f);
                byte[] buf = new byte[64];
                int n = fis.read(buf);
                fis.close();
                Log.i(TAG, "READ " + path + " → OK (" + n + " bytes)");
            }
        } catch (Exception e) {
            Log.i(TAG, "READ " + path + " → " + e.getMessage());
        }
    }

    private void testWrite(String path) {
        try {
            FileOutputStream fos = new FileOutputStream(path);
            fos.write("probe".getBytes());
            fos.close();
            new File(path).delete();
            Log.i(TAG, "WRITE " + path + " → OK");
        } catch (Exception e) {
            Log.i(TAG, "WRITE " + path + " → " + e.getMessage());
        }
    }

    private void testBind(int port) {
        try {
            ServerSocket s = new ServerSocket(port);
            s.close();
            Log.i(TAG, "BIND :" + port + " → OK");
        } catch (Exception e) {
            Log.i(TAG, "BIND :" + port + " → " + e.getMessage());
        }
    }
}
