fn client(builder: rustls_config::ClientConfig) {
    let _danger = builder.danger_accept_invalid_certs(true);
}
