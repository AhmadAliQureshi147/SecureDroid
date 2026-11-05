using System.Net.Http;

public class Trust {
    public static HttpClientHandler Handler() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true;
        return handler;
    }
}
