package example

import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.X509TrustManager

class KotlinTrust : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    val verifier: HostnameVerifier = HostnameVerifier { _, _ -> true }
}
