/*
 * Copyright (C) 2015-2022 IoT.bzh Pionix, Chargebyte and Everest contributors
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Rust largely inspired from Everest C++ git@github.com:/EVerest/libiso15118.git
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */

use crate::prelude::*;
use afbv4::prelude::*;
use std::net;

pub struct TlsConnection {
    session: &'static GnuTlsSession,
    client: TcpClient,
}

impl Drop for TlsConnection {
    fn drop(&mut self) {
        println!("**** TlsConnection drop");
    }
}

impl NetConnection for TlsConnection {
    #[track_caller]
    fn get_sockfd(&self) -> Result<i32, AfbError> {
        let sockfd = self.client.get_sockfd()?;
        Ok(sockfd)
    }

    #[track_caller]
    fn get_source(&self) -> net::SocketAddr {
        self.client.get_source()
    }

    #[track_caller]
    fn get_data(&self, buffer: &mut [u8]) -> Result<u32, AfbError> {
        let count = self.session.recv(buffer)?;
        Ok(count as u32)
    }
    #[track_caller]
    fn put_data(&self, buffer: &[u8]) -> Result<usize, AfbError> {
        let count = self.session.send(buffer)?;
        Ok(count)
    }

    #[track_caller]
    fn close(&self) -> Result <(), AfbError> {
        let _ = self.client.close();
        let _ = self.session.close();
        Ok(())
    }
}

impl TlsConnection {
    #[track_caller]
    pub fn new(config: &TlsConfig, client: TcpClient) -> Result<Self, AfbError> {
        // create a new tls segit pullssion for server TlsConfig
        let sockfd = client.get_sockfd()?;
        let session = GnuTlsSession::new(&config.gtls, sockfd)?;
        // &session.set_server_sni(config);

        let connection = TlsConnection { session, client };
        Ok(connection)
    }

    #[track_caller]
    pub fn get_version(&self) -> GnuTlsVersion {
        self.session.get_version()
    }
    #[track_caller]
    pub fn client_handshake(&self) -> Result<(), AfbError> {
        self.session.client_handshake()?;
        Ok(())
    }

    #[track_caller]
    pub fn check_pending(&self) -> bool {
        self.session.check_pending()
    }

}
#[derive(Clone)]
pub struct TlsConfig {
    pub gtls: GnuTlsConfig,
}

// Parse certificate keys
impl TlsConfig {
    pub fn new(
        cert_chain: &str,
        key_file: &str,
        key_pin: Option<&str>,
        ca_trust: Option<&str>,
        tls_psk: Option<&'static str>,
        psk_log: Option<&'static str>,
        tls_verbosity: i32,
        tls_proto:  Option<&'static str>,
    ) -> Result<&'static Self, AfbError> {
        let config = GnuTlsConfig::new(
            cert_chain,
            key_file,
            key_pin,
            ca_trust,
            tls_psk,
            psk_log,
            tls_verbosity,
            tls_proto,
        )?;

        let handle = Box::new(TlsConfig { gtls: config });
        Ok(Box::leak(handle))
    }

    pub fn set_verbosity(&self, level: i32) {
        self.gtls.set_verbosity(level)
    }
}