package com.archive.user;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;

import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "ArchivePlayback")
public class ArchivePlaybackPlugin extends Plugin {
    private static final int NOTIFICATION_REQUEST = 4102;
    private PluginCall pendingNotificationCall;

    @PluginMethod
    public void requestNotifications(PluginCall call) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            getActivity().checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            pendingNotificationCall = call;
            getActivity().requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATION_REQUEST);
            return;
        }
        call.resolve();
    }

    @Override
    protected void handleRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.handleRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == NOTIFICATION_REQUEST && pendingNotificationCall != null) {
            boolean granted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            if (granted) pendingNotificationCall.resolve();
            else pendingNotificationCall.reject("NOTIFICATION_PERMISSION_DENIED");
            pendingNotificationCall = null;
        }
    }

    @PluginMethod
    public void start(PluginCall call) {
        Intent intent = new Intent(getContext(), ArchivePlaybackService.class)
            .putExtra("title", call.getString("title", "تشغيل صوتي"))
            .putExtra("artist", call.getString("artist", "Archive"));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) getContext().startForegroundService(intent);
        else getContext().startService(intent);
        call.resolve();
    }

    @PluginMethod
    public void update(PluginCall call) {
        Intent intent = new Intent(getContext(), ArchivePlaybackService.class)
            .putExtra("title", call.getString("title", "تشغيل صوتي"))
            .putExtra("artist", call.getString("artist", "Archive"));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) getContext().startForegroundService(intent);
        else getContext().startService(intent);
        call.resolve();
    }

    @PluginMethod
    public void stop(PluginCall call) {
        getContext().stopService(new Intent(getContext(), ArchivePlaybackService.class));
        call.resolve();
    }
}
