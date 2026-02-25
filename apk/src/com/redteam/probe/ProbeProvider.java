package com.redteam.probe;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.util.Log;
import java.io.*;

/**
 * Content provider that can read files on behalf of the app.
 * Query: content query --uri content://com.redteam.probe.provider/file --arg /path/to/file
 */
public class ProbeProvider extends ContentProvider {
    private static final String TAG = "RedTeamProbe";

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"path", "content", "error"});
        
        String path = null;
        if (selectionArgs != null && selectionArgs.length > 0) path = selectionArgs[0];
        if (path == null && uri.getPathSegments().size() > 1) path = "/" + uri.getPath().substring("/file/".length());

        if (path != null) {
            try {
                File f = new File(path);
                if (f.isDirectory()) {
                    String[] list = f.list();
                    StringBuilder sb = new StringBuilder();
                    if (list != null) { for (String s : list) { sb.append(s).append("\n"); } }
                    cursor.addRow(new Object[]{path, sb.length() > 0 ? sb.toString() : "empty", null});
                } else {
                    byte[] buf = new byte[4096];
                    FileInputStream fis = new FileInputStream(f);
                    int n = fis.read(buf);
                    fis.close();
                    cursor.addRow(new Object[]{path, new String(buf, 0, n), null});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{path, null, e.getMessage()});
            }
        }
        return cursor;
    }

    @Override
    public String getType(Uri uri) { return "text/plain"; }
    @Override
    public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
