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

use afbv4::prelude::AfbError;
use std::net;

pub const IPV6_ANY:[u8;16]=[0;16];
pub trait NetConnection {
    fn get_source(&self) -> net::SocketAddr;
    fn get_data(&self, buffer: &mut [u8]) -> Result<u32, AfbError>;
    fn put_data(&self, buffer: &[u8]) -> Result<usize, AfbError>;
    fn get_sockfd(&self) -> Result<i32, AfbError>;
    fn close(&self) -> Result<(), AfbError>;
}