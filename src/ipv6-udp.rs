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
use std::sync::{Mutex, MutexGuard};

#[derive(Clone)]
pub struct SdpState {
    pub remote_addr6: Option<SockAddrV6>,
}

pub struct SdpServer {
    data_cell: Mutex<SdpState>,
    uid: &'static str,
    socket: SocketSdpV6,
}

impl SdpServer {
    pub fn new(uid: &'static str, iface: &str, port: u16) -> Result<Self, AfbError> {
        let socket = SocketSdpV6::new()?;
        socket.bind(iface, port)?;
        socket.multicast_join(IP6_BROADCAST_ANY)?;
        afb_log_msg!(
            Notice,
            None,
            "{} accept anycast-ipv6 udp:{}@{}",
            uid,
            port,
            iface
        );

        let handle = SdpServer {
            data_cell: Mutex::new(SdpState { remote_addr6: None }),
            socket,
            uid,
        };
        Ok(handle)
    }

    pub fn get_sockfd(&self) -> i32 {
        self.socket.get_sockfd()
    }

    pub fn get_uid(&self) -> &'static str {
        self.uid
    }

    #[track_caller]
    fn get_handle(&self) -> Result<MutexGuard<'_, SdpState>, AfbError> {
        match self.data_cell.lock() {
            Err(_) => return afb_error!("sdp-state-get", "fail to access &mut data_cell"),
            Ok(value) => Ok(value),
        }
    }

    pub fn read_buffer(&self, buffer: &mut [u8]) -> Result<(), AfbError> {
        let remote_addr6 = self.socket.recvfrom(buffer.as_mut_ptr(), buffer.len())?;

        // request is valid, update remote source ipv6 addr
        afb_log_msg!(Debug, None, "Received sdp from addr6:{:0x?}", unsafe {
            &remote_addr6.addr.sin6_addr.__in6_u.__u6_addr16
        });
        let mut data_cell = self.get_handle()?;
        data_cell.remote_addr6 = Some(remote_addr6);
        Ok(())
    }

    pub fn send_buffer_to(&self,  buffer: &[u8], remote_addr6: &SockAddrV6) -> Result<(), AfbError> {
        afb_log_msg!(Debug, None, "Sendto sdp to addr6:{}", remote_addr6);
        self.socket.sendto(buffer, &remote_addr6)?;
        Ok(())
    }

    pub fn send_buffer(&self, buffer: &[u8]) -> Result<(), AfbError> {
        let data_cell = self.get_handle()?;
        let remote_addr6 = match &data_cell.remote_addr6 {
            Some(value) => {
                // copy destination addr but should keep source ipv6 scope
                let destination = value.addr;
                SockAddrV6 { addr: destination }
            }
            None => return afb_error!("sdp-respose-state", "No destination defined"),
        };

        afb_log_msg!(Debug, None, "Responding sdp to addr6:{}", remote_addr6);
        self.socket.sendto(buffer, &remote_addr6)?;
        Ok(())
    }
}
