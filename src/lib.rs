/*
 * Copyright (C) 2015-2022 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Reference:
 *   https://www.zupzup.org/epoll-with-rust/index.html
 *   https://github.com/cienporcien/libiso15118/tree/dash-20-dash-2-poc
 */

#![doc(
    html_logo_url = "https://iot.bzh/images/defaults/company/512-479-max-transp.png",
    html_favicon_url = "https://iot.bzh/images/defaults/favicon.ico"
)]

#[cfg(test)]
#[path = "../test/encoder-test.rs"]
mod test;

#[cfg(not(afbv4))]
extern crate afbv4;

#[path = "../capi/capi-network.rs"]
mod network;

#[path = "ipv6-interface.rs"]
mod interface;

#[path = "ipv6-udp.rs"]
mod udp;

#[path = "ipv6-tcp.rs"]
mod tcp;

#[path = "ipv6-tls.rs"]
mod tls;

pub mod prelude {
    pub use crate::network::*;
    pub use crate::interface::*;
    pub use crate::udp::*;
    pub use crate::tls::*;
    pub use crate::tcp::*;
}