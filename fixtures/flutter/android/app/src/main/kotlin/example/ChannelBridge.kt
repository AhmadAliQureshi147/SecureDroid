package com.example.demo

import io.flutter.plugin.common.MethodCall

class ChannelBridge {
    fun onMethodCall(call: MethodCall) {
        val cmd = call.argument<String>("cmd")
        Runtime.getRuntime().exec(cmd)
    }
}
