package com.example.demo;

import com.facebook.react.bridge.ReactMethod;

public class RunModule {
    @ReactMethod
    public void run(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}
