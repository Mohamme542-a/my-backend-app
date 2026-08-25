package com.archive.user;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(android.os.Bundle savedInstanceState) {
        registerPlugin(ArchivePlaybackPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
