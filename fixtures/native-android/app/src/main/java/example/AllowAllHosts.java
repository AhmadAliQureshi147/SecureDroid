package com.example.secure;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public final class AllowAllHosts implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}
