#RUST binding for ipv6 & gnutls support UDP,TCP &TLS 1.3

This crate provide a Rust API leveraging C-GnuTLS cryto API. It interface standard Rust stream for TCP and TLS connection. As well as UDP multicast for Iso15118 SDP(Service Discovery Protocol).

## Dependencies:
* gnutls-devel
* clang

## Api

Check iso15118-binding-rs | iso15118-simulator-rs for further apis

* let sdp_addr6 = get_iface_addrs(&self.iface, self.prefix)?;
* let tcp= TcpServer::new(api,"tls-wserver", &sdp_addr6, self.tls_port)?;
* let sdp = SdpServer::new(api,"sdp-server", self.iface, self.sdp_port)?;
* let tcp_client = TcpClient::new(addr6, port, self.scope)?;
* let tls_client = TlsConnection::new(&self.tls_conf, tcp_client)?;
* let tls_connection = TlsConnection::new(ctx.config, tls_client)?;

## Examples:

* http:://github.com/tux-evse/iso15118-binding-rs
* https://github.com/tux-evse/iso15118-simulator-rs

The API target asynchronous architecture. Nevertheless it should also work synchronously when needed. While independent of any async framework; it reference platform is afb-librust (https://github.com/redpesk-common/afb-librust)

```
fn async_tls_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &mut AsyncTlsCtx) -> Result<(), AfbError> {
    if revent == AfbEvtFdPoll::IN.bits() {
        let tls_client = ctx.tls.accept_client()?;
        let source = tls_client.get_source();
        let sockfd = tls_client.get_sockfd()?;
        let tls_connection = TlsConnection::new(ctx.config, tls_client)?;
        tls_connection.client_handshake()?;

        afb_log_msg!(
            Notice,
            None,
            "New connection client:{} protocol:{}",
            source,
            tls_connection.get_version().to_string()
        );

        AfbEvtFd::new("tls-client")
            .set_fd(sockfd)
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(async_tls_client_cb)
            .set_context(AsyncTlsClientCtx {
                connection: tls_connection,
                data_len: 0,
                payload_len: 0,
                controler: IsoControler::new()?,
                stream: ExiStream::new(),
            })
            .start()?;
    }
    Ok(())
}
```

