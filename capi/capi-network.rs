use std::io::Write;
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
 * ref: https://gnutls.org/manual/html_node/Echo-server-with-X_002e509-authentication.html
 *      https://www.gnutls.org/reference/gnutls-gnutls.html
 *      https://github.com/defuse/gnutls-psk/blob/master/server.c
 *
 * Nota: did not implement revocation list CRLs
 */
use ::std::os::raw;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::mem;
use std::net;
use std::ptr;
use std::rc::Rc;
use std::slice;
use std::sync::Mutex;

const MAX_ERROR_LEN: usize = 256;
pub mod cglue {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!("_capi-network.rs");
}

pub fn get_perror() -> String {
    let mut buffer = [0 as ::std::os::raw::c_char; MAX_ERROR_LEN];
    unsafe {
        cglue::strerror_r(
            *cglue::__errno_location(),
            &mut buffer as *mut raw::c_char,
            MAX_ERROR_LEN,
        )
    };
    let cstring = unsafe { CStr::from_ptr(&mut buffer as *const raw::c_char) };
    let slice: &str = cstring.to_str().unwrap();
    slice.to_owned()
}

pub fn gtls_perror(code: i32) -> String {
    let error = unsafe { cglue::gnutls_strerror(code) };
    let cstring = unsafe { CStr::from_ptr(error as *const raw::c_char) };
    let slice: &str = cstring.to_str().unwrap();
    slice.to_owned()
}

//use crate::prelude::*;
use afbv4::prelude::*;

pub const IP6_BROADCAST_ANY: [u8; cglue::C_INET6_ADDR_LEN] =
    [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

#[derive(Clone, Debug)]
pub struct IfaceAddr6 {
    pub addr: net::Ipv6Addr,
    pub scope: u32,
}

impl IfaceAddr6 {
    pub fn get_addr(&self) -> net::Ipv6Addr {
        self.addr
    }

    pub fn get_scope(&self) -> u32 {
        self.scope
    }
}

pub fn get_iface_addrs(iface: &str, filter: u16) -> Result<IfaceAddr6, AfbError> {
    // scan linux network interfaces
    let mut ifaddrs = mem::MaybeUninit::<*mut cglue::ifaddrs>::uninit();
    let status = unsafe { cglue::getifaddrs(ifaddrs.as_mut_ptr()) };
    let start = unsafe { ifaddrs.assume_init() };
    if status < 0 {
        return afb_error!(
            "ipv6-iface-scan",
            "fail to scan network interfaces {}",
            gtls_perror(status)
        );
    }

    // translate iface name to a valid C string
    let iface_name = match CString::new(iface) {
        Ok(value) => value,
        Err(_) => return afb_error!("ipv6-iface-import", "fail to import iface:{}", iface),
    };

    match unsafe { start.as_ref() } {
        None => return afb_error!("ipv6-iface-empty", "no network interface"),
        Some(_) => {}
    };

    let mut idx = 0;
    let mut next = start;
    let addr = loop {
        let ifa = match unsafe { next.as_ref() } {
            None => break None,
            Some(start) => {
                idx = idx + 1; // keep iface index for ipv6 bind
                start
            }
        };

        println!(
            "name:{} index:{}",
            unsafe { CStr::from_ptr(ifa.ifa_name).to_str().unwrap() },
            idx
        );

        // iface name match ?
        if iface_name.as_ref() != unsafe { CStr::from_ptr(ifa.ifa_name).as_ref() } {
            next = ifa.ifa_next;
            continue;
        }

        // extract sockaddr data
        let saddr = match unsafe { (ifa.ifa_addr as *mut cglue::sockaddr_in6).as_ref() } {
            Some(addr) => addr,
            None => {
                next = ifa.ifa_next;
                continue;
            }
        };

        // iface is IPV6 ?
        if saddr.sin6_family != cglue::C_AF_INET6 {
            next = ifa.ifa_next;
            continue;
        }

        // filter addrv6 (local-link=0xfe80)
        let addr_prefix = unsafe { cglue::htons(saddr.sin6_addr.__in6_u.__u6_addr16[0]) };
        if filter != 0 && addr_prefix != filter {
            next = ifa.ifa_next;
            continue;
        }

        // get a valid ip6-addr
        break Some(saddr);
    };

    let response = match addr {
        None => {
            return afb_error!(
                "ipv6-iface-match",
                "fail to find IPV6 iface:'{}' filter:'{:#x}'",
                iface,
                filter
            )
        }
        Some(saddr) => IfaceAddr6 {
            addr: net::Ipv6Addr::from(unsafe { saddr.sin6_addr.__in6_u.__u6_addr8 }),
            scope: saddr.sin6_scope_id,
        },
    };
    unsafe { cglue::freeifaddrs(start) };
    Ok(response)
}

#[derive(Clone)]
pub struct SockAddrV6 {
    pub addr: cglue::sockaddr_in6,
}

impl SockAddrV6 {
    pub fn new(addr: &[u8;16], port: u16, scope: u32) -> Self {
        let mut socket_sdp = unsafe { mem::zeroed::<cglue::sockaddr_in6>() };
        socket_sdp.sin6_family = cglue::C_AF_INET6;
        socket_sdp.sin6_port = unsafe { cglue::htons(port) };
        socket_sdp.sin6_scope_id= scope;
        socket_sdp.sin6_addr.__in6_u.__u6_addr8 = addr.clone(); // 0= IPV6_ANY
        Self { addr: socket_sdp}
    }
}

impl fmt::Display for SockAddrV6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = "ipv6:[".to_string();
        for idx in 0..8 {
            let slot = unsafe { self.addr.sin6_addr.__in6_u.__u6_addr16[idx] };
            let key = format!("{:#02x}:", unsafe { cglue::ntohs(slot) });
            text.push_str(&key.as_str());
        }
        text.push_str("]");
        write!(f, "{}", text)
    }
}

#[derive(Clone)]
pub struct SocketSdpV6 {
    sockfd: i32,
}

impl SocketSdpV6 {
    pub fn new() -> Result<Self, AfbError> {
        const ENABLE: i32 = 1;

        let sockfd = unsafe {
            cglue::socket(
                cglue::C_AF_INET6 as i32,
                cglue::C_SOCK_DGRAM,
                cglue::C_IPPROTO_UDP,
            )
        };
        if sockfd < 0 {
            return afb_error!(
                "ipv6-socket-open",
                "fail to create IPv6 socket {}",
                get_perror()
            );
        }

        let status = unsafe {
            cglue::setsockopt(
                sockfd,
                cglue::C_SOL_SOCKET,
                cglue::C_SO_REUSEPORT,
                &ENABLE as *const _ as *mut raw::c_void,
                mem::size_of::<i32>() as u32,
            )
        };
        if status < 0 {
            unsafe { cglue::close(sockfd) };
            return afb_error!(
                "ipv6-socket-setopt",
                "fail to set reuseport option {}",
                get_perror()
            );
        }

        Ok(SocketSdpV6 { sockfd })
    }

    pub fn get_sockfd(&self) -> i32 {
        self.sockfd
    }

    pub fn attach_dev(&self, iface_name: &str) -> Result<(), AfbError> {
        let cstring = match CString::new(iface_name) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!(
                    "ipv6-socket-attach",
                    "fail to translate iface-name:{}",
                    iface_name
                )
            }
        };

        let rc = unsafe {
            cglue::setsockopt(
                self.sockfd,
                cglue::C_SOL_SOCKET,
                cglue::C_BINDTODEVICE,
                cstring.as_ptr() as *const _ as *const raw::c_void,
                iface_name.len() as u32,
            )
        };
        if rc < 0 {
            return afb_error!(
                "ipv6-socket-attach",
                "fail device binding iface:{} err:{}",
                iface_name,
                get_perror()
            );
        }
        Ok(()) //ifr.ifr_if index
    }

    pub fn bind(&self, iface: &str, port: u16) -> Result<(), AfbError> {
        let mut socket_sdp = unsafe { mem::zeroed::<cglue::sockaddr_in6>() };
        socket_sdp.sin6_family = cglue::C_AF_INET6;
        socket_sdp.sin6_port = unsafe { cglue::htons(port) };
        // socket_sdp.sin6_addr = [0;] IPV6_ANY

        if iface != "" {
            self.attach_dev(iface)?;
        }
        let rc = unsafe {
            cglue::bind(
                self.sockfd,
                &socket_sdp as *const _ as *mut cglue::sockaddr,
                mem::size_of::<cglue::sockaddr_in6>() as u32,
            )
        };
        if rc < 0 {
            return afb_error!(
                "ipv6-socket-bind",
                "fail device bind port:{} err:{}",
                port,
                get_perror()
            );
        }
        Ok(())
    }

    pub fn multicast_join(
        &self,
        mcast_addr: [u8; cglue::C_INET6_ADDR_LEN],
    ) -> Result<(), AfbError> {
        let iface_num = 0;

        let in6_addr = cglue::in6_addr {
            __in6_u: cglue::in6_addr__bindgen_ty_1 {
                __u6_addr8: mcast_addr,
            },
        };

        let ipv6_mreq = cglue::ipv6_mreq {
            ipv6mr_multiaddr: in6_addr,
            ipv6mr_interface: iface_num,
        };

        let status = unsafe {
            cglue::setsockopt(
                self.sockfd,
                cglue::C_IPPROTO_IPV6,
                cglue::C_IPV6_JOIN_GROUP,
                &ipv6_mreq as *const _ as *mut raw::c_void,
                mem::size_of::<cglue::ipv6_mreq>() as u32,
            )
        };
        if status < 0 {
            unsafe { cglue::close(self.sockfd) };
            return afb_error!(
                "ipv6-socket-setopt",
                "fail to set ipv6_joint_group option {}",
                get_perror()
            );
        }

        Ok(())
    }

    pub fn recvfrom(&self, buffer: *mut u8, len: usize) -> Result<SockAddrV6, AfbError> {
        let mut remote_addr6 = unsafe { mem::zeroed::<cglue::sockaddr_in6>() };
        let mut remote_len = mem::size_of::<cglue::sockaddr_in6>();

        let count = unsafe {
            cglue::recvfrom(
                self.sockfd,
                buffer as *mut raw::c_void,
                len,
                0,
                &mut remote_addr6 as *const _ as *mut cglue::sockaddr,
                &mut remote_len as *const _ as *mut cglue::socklen_t,
            )
        };
        if count < 0 || remote_len != mem::size_of::<cglue::sockaddr_in6>() {
            unsafe { cglue::close(self.sockfd) };
            return afb_error!(
                "ipv6-socket-recvfrom",
                "fail to read sdp socket len:{} err:{}",
                remote_len,
                get_perror()
            );
        }

        let source = SockAddrV6 { addr: remote_addr6 };

        Ok(source)
    }

    pub fn sendto(&self, buffer: &[u8], destination: &SockAddrV6) -> Result<(), AfbError> {
        let len = unsafe {
            cglue::sendto(
                self.sockfd,
                buffer.as_ptr() as *const _ as *mut raw::c_void,
                buffer.len(),
                0,
                &destination.addr as *const _ as *mut cglue::sockaddr,
                mem::size_of::<cglue::sockaddr_in6>() as cglue::socklen_t,
            )
        };
        if len != buffer.len() as isize {
            unsafe { cglue::close(self.sockfd) };
            return afb_error!(
                "ipv6-socket-recvfrom",
                "fail to send sdp socket len:{} err:{}",
                len,
                get_perror()
            );
        }

        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn client_certificate_cb(session: cglue::gnutls_session_t) -> raw::c_int {
    // retrieve tls session from gnutls_session_set_ptr()
    let _tls_session = match unsafe {
        (cglue::gnutls_session_get_ptr(session) as *const GnuTlsSession).as_ref()
    } {
        Some(data) => data,
        None => {
            afb_log_msg!(
                Critical,
                None,
                "gtls-client-certificate: no session provided to callback"
            );
            return -1;
        }
    };

    let status: u32 = 0;
    let rc = unsafe {
        cglue::gnutls_certificate_verify_peers2(session, &status as *const _ as *mut u32)
    };
    if rc < 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: fail to verify certificate"
        );
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }
    if status & cglue::C_GNUTLS_CERT_INVALID != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate is not trusted"
        );
    }
    if status & cglue::C_GNUTLS_CERT_SIGNER_NOT_FOUND != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate hasn't got a known issuer"
        );
    }
    if status & cglue::C_GNUTLS_CERT_REVOKED != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate has been revoked"
        );
    }
    if status & cglue::C_GNUTLS_CERT_EXPIRED != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate has expired"
        );
    }
    if status & cglue::C_GNUTLS_CERT_NOT_ACTIVATED != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate is not yet activated"
        );
    }
    if status != 0 {
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    if unsafe { cglue::gnutls_certificate_type_get(session) != cglue::C_GNUTLS_CRT_X509 } {
        afb_log_msg!(Error, None, "gtls-client-certificate: not X509 certificate");
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    let mut cert = mem::MaybeUninit::<cglue::gnutls_x509_crt_t>::uninit();
    let cert = if unsafe { cglue::gnutls_x509_crt_init(cert.as_mut_ptr()) } < 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: fail to init client x509 session"
        );
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    } else {
        unsafe { cert.assume_init() }
    };

    let cert_list_size: u32 = 0;
    let cert_list = unsafe {
        cglue::gnutls_certificate_get_peers(session, &cert_list_size as *const _ as *mut u32)
    };
    if cert_list == 0 as *const cglue::gnutls_datum_t {
        afb_log_msg!(Error, None, "gtls-client-certificate: no certificate found");
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    // check only the first certificate - seems to be what curl does
    if unsafe { cglue::gnutls_x509_crt_import(cert, cert_list, cglue::C_GNUTLS_X509_FMT_DER) } < 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: fail parsing first certificate"
        );
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    unsafe { cglue::gnutls_x509_crt_deinit(cert) };
    0
}

#[no_mangle]
pub extern "C" fn verbosity_log_cb(level: i32, text: *const raw::c_char) {
    let cstring = unsafe { CStr::from_ptr(text) };
    let slice: &str = cstring.to_str().unwrap();
    afb_log_msg!(Debug, None, "GTLS:{} {}", level, slice);
}

#[no_mangle]
pub extern "C" fn pre_share_key_cb(
    session: cglue::gnutls_session_t,
    _username: *const raw::c_char,
    key_out: *mut cglue::gnutls_datum_t,
) -> raw::c_int {
    // transform gnutls_session_t into GnuTlsSessionCtx to retreive psk
    let tls_session = match unsafe {
        (cglue::gnutls_session_get_ptr(session) as *const GnuTlsSession).as_ref()
    } {
        Some(data) => data,
        None => {
            afb_log_msg!(
                Critical,
                None,
                "gtls-psk-callback: no session provided to callback"
            );
            return -1;
        }
    };

    let psk_session = match &tls_session.psk_key {
        Some(key) => key,
        None => {
            afb_log_msg!(Critical, None, "gtls-psk-callback: null pre-share_key");
            return -1;
        }
    };

    let key_session = match unsafe { key_out.as_mut() } {
        Some(data) => data,
        None => {
            afb_log_msg!(
                Critical,
                None,
                "gtls-psk-callback: no session key_handle provided"
            );
            return -1;
        }
    };
    // init gtls internal session with config pre_shared_key
    let key_size = tls_session.psk_len;
    key_session.size = key_size as u32;
    key_session.data = unsafe { cglue::malloc(key_size as u64) as *mut u8 };
    unsafe {
        ptr::copy_nonoverlapping(
            psk_session.as_ptr(),
            key_session.data as *mut raw::c_char,
            key_size,
        )
    }
    0
}

#[no_mangle]
pub extern "C" fn gnutls_keylog_cb(
    session: cglue::gnutls_session_t,
    label: *const raw::c_char,
    secret: *const cglue::gnutls_datum_t,
) -> i32 {
    // reference: https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html

    let tls_session = match unsafe {
        (cglue::gnutls_session_get_ptr(session) as *const GnuTlsSession).as_ref()
    } {
        Some(data) => data,
        None => {
            afb_log_msg!(
                Critical,
                None,
                "gtls-log-callback: no session provided to callback"
            );
            return -1;
        }
    };

    let secret = match unsafe { secret.as_ref() } {
        None => return -1,
        Some(value) => value,
    };

    let cstring = unsafe { CStr::from_ptr(label as *const raw::c_char) };
    let secret_label = cstring.to_str().unwrap().to_string();

    let mut client_data = mem::MaybeUninit::<cglue::gnutls_datum_t>::uninit();
    let mut server_data = mem::MaybeUninit::<cglue::gnutls_datum_t>::uninit();
    let (client_data, _server_data) = unsafe {
        cglue::gnutls_session_get_random(
            session,
            client_data.as_mut_ptr(),
            server_data.as_mut_ptr(),
        );
        (client_data.assume_init(), server_data.assume_init())
    };
    let mut client_random = "".to_string();
    let slice = unsafe { slice::from_raw_parts(client_data.data, client_data.size as usize) };
    for byte in slice {
        client_random = client_random + format!("{:02x}", byte).as_str();
    }

    let mut session_secret = "".to_string();
    let slice = unsafe { slice::from_raw_parts(secret.data, secret.size as usize) };
    for byte in slice {
        session_secret = session_secret + format!("{:02x}", byte).as_str();
    }

    let _ = tls_session
        .logger
        .write(format!("{} {} {}\n", secret_label, client_random, session_secret).as_str());
    0
}
pub struct TlsKeyLogger {
    fd: Option<Mutex<File>>,
}

impl TlsKeyLogger {
    pub fn new(log_path: Option<&str>) -> Result<Self, AfbError> {
        let fd = match log_path {
            None => None,
            Some(path) => {
                let file = match File::create(path) {
                    Ok(handle) => handle,
                    Err(error) => {
                        return afb_error!(
                            "gtls-config-log",
                            "fail to create log file:{} error:{}",
                            path,
                            error
                        )
                    }
                };
                Some(Mutex::new(file))
            }
        };

        let handle = TlsKeyLogger { fd };
        Ok(handle)
    }

    pub fn write(&self, text: &str) -> Result<(), AfbError> {
        match &self.fd {
            None => {}
            Some(handle) => {
                let mut fd = handle.lock().unwrap();
                match fd.write_all(text.as_bytes()) {
                    Ok(_) => {}
                    Err(error) => {
                        return afb_error!(
                            "gtls-config-log",
                            "fail to push log entry error:{}",
                            error
                        )
                    }
                }
            }
        }
        Ok(())
    }

    pub fn activate_log(&self, session: cglue::gnutls_session_t) {
        match &self.fd {
            None => {}
            Some(_handle) => {
                unsafe {
                    cglue::gnutls_session_set_keylog_function(session, Some(gnutls_keylog_cb))
                };
            }
        }
    }
}

pub struct GnuTlsSession {
    xcred: cglue::gnutls_certificate_credentials_t,
    xsession: cglue::gnutls_session_t,
    psk_key: Option<CString>,
    psk_len: usize,
    logger: Rc<TlsKeyLogger>,
}

#[repr(u32)]
pub enum GnuTlsVersion {
    TLS1_2 = cglue::gnutls_protocol_t_GNUTLS_TLS1_2,
    TLS1_3 = cglue::gnutls_protocol_t_GNUTLS_TLS1_3,
    DTLS1_2 = cglue::gnutls_protocol_t_GNUTLS_DTLS1_2,
    UNSUPPORTED = cglue::gnutls_protocol_t_GNUTLS_VERSION_UNKNOWN,
}

impl GnuTlsVersion {
    pub fn from_u32(value: u32) -> Self {
        match value as cglue::gnutls_protocol_t {
            cglue::gnutls_protocol_t_GNUTLS_TLS1_2 => GnuTlsVersion::TLS1_2,
            cglue::gnutls_protocol_t_GNUTLS_TLS1_3 => GnuTlsVersion::TLS1_3,
            cglue::gnutls_protocol_t_GNUTLS_DTLS1_2 => GnuTlsVersion::DTLS1_2,
            _ => GnuTlsVersion::UNSUPPORTED,
        }
    }

    pub fn to_u32(&self) -> cglue::gnutls_protocol_t {
        match self {
            GnuTlsVersion::TLS1_2 => cglue::gnutls_protocol_t_GNUTLS_TLS1_2,
            GnuTlsVersion::TLS1_3 => cglue::gnutls_protocol_t_GNUTLS_TLS1_3,
            GnuTlsVersion::DTLS1_2 => cglue::gnutls_protocol_t_GNUTLS_DTLS1_2,
            GnuTlsVersion::UNSUPPORTED => cglue::gnutls_protocol_t_GNUTLS_VERSION_UNKNOWN,
        }
    }

    pub fn to_string(&self) -> String {
        let value = self.to_u32();
        let cstring = unsafe {
            let buffer = cglue::gnutls_protocol_get_name(value);
            CStr::from_ptr(buffer)
        };
        let slice: &str = cstring.to_str().unwrap();
        slice.to_owned()
    }
}

impl Drop for GnuTlsSession {
    fn drop(&mut self) {
        unsafe { cglue::gnutls_deinit(self.xsession) };
        let boxe = unsafe { Box::from_raw(self) };
        drop(boxe);
    }
}

impl GnuTlsSession {
    pub fn new(config: &GnuTlsConfig, sockfd: i32) -> Result<&'static Self, AfbError> {
        let xcred = config.xcred;
        let xsession = unsafe {
            let mut session = mem::MaybeUninit::<cglue::gnutls_session_t>::uninit();
            let status = cglue::gnutls_init(
                session.as_mut_ptr(),
                cglue::gnutls_init_flags_t_GNUTLS_SERVER,
            );
            let session = session.assume_init();
            if status < 0 {
                return afb_error!(
                    "gtls-session-tlsinit",
                    "fail to initialise session error:{}",
                    gtls_perror(status)
                );
            }
            session
        };

        let status = unsafe { cglue::gnutls_set_default_priority(xsession) };
        if status < 0 {
            return afb_error!(
                "gtls-session-default",
                "fail to set default priority error:{}",
                gtls_perror(status)
            );
        }

        unsafe {
            let mut error = mem::MaybeUninit::<*mut raw::c_char>::uninit();
            let status = cglue::gnutls_priority_set_direct(
                xsession,
                config.priority.as_ptr(),
                error.as_mut_ptr() as *mut *const raw::c_char,
            );
            let error = error.assume_init();
            if status < 0 {
                return afb_error!(
                    "gtls-session-priority",
                    "fail to set priority:{:?} error:{}",
                    config.priority,
                    gtls_perror(status)
                );
            }
            error
        };

        let status = unsafe {
            cglue::gnutls_credentials_set(
                xsession,
                config.authent,
                xcred as *const _ as *mut raw::c_void,
            )
        };
        if status < 0 {
            return afb_error!(
                "gtls-session-credential",
                "fail to set priority error:{}",
                gtls_perror(status)
            );
        }

        unsafe {
            // advertise trusted CA to peer
            cglue::gnutls_certificate_send_x509_rdn_sequence(xsession, 0);

            // request client cetificate, but do not enforce it
            cglue::gnutls_certificate_server_set_request(
                xsession,
                cglue::gnutls_certificate_request_t_GNUTLS_CERT_REQUEST,
            );
            cglue::gnutls_handshake_set_timeout(
                xsession,
                cglue::C_GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT as u32,
            );
        };

        unsafe {
            cglue::gnutls_transport_set_ptr(xsession, sockfd as cglue::gnutls_transport_ptr_t)
        };

        let (psk_key, psk_len) = match config.tls_psk {
            Some(value) => match CString::new(value) {
                Ok(name) => (Some(name), value.len()),
                Err(_) => {
                    return afb_error!(
                        "gtls-session-client_psk",
                        "fail converting psk string:{}",
                        value
                    )
                }
            },
            None => (None, 0),
        };

        config.logger.activate_log(xsession);

        let this = Box::leak(Box::new(GnuTlsSession {
            xcred,
            xsession,
            psk_key,
            psk_len,
            logger: config.logger.clone(),
        }));

        unsafe { cglue::gnutls_session_set_ptr(xsession, this as *const _ as *mut raw::c_void) };
        Ok(this)
    }

    #[allow(dead_code)]
    #[track_caller]
    pub fn get_target_sni(&self) -> Result<String, AfbError> {
        //retreive client sni hostname target (Fulup TDB check with Jose why it fails)
        const MAX_HOST_LEN: usize = 255;
        let server_sni = unsafe {
            let mut hostname_sni = mem::MaybeUninit::<[u8; MAX_HOST_LEN]>::uninit();
            let mut hostname_type: u32 = 0;
            let status = cglue::gnutls_server_name_get(
                self.xsession,
                hostname_sni.as_mut_ptr() as *mut raw::c_void,
                MAX_HOST_LEN as *mut usize,
                &mut hostname_type as *mut u32,
                0,
            );
            if status < 0 {
                return afb_error!(
                    "gtls-session-hostname",
                    "fail to retreive client sni hostname error:{}",
                    gtls_perror(status)
                );
            }
            let sni = hostname_sni.assume_init();
            CStr::from_ptr(&sni as *const _ as *mut raw::c_char)
        };

        let sni = match server_sni.to_str() {
            Ok(value) => value,
            Err(_) => return afb_error!("gtls-session-hostname", "invalid client SNI hostname",),
        };

        afb_log_msg!(Debug, None, "gtls client hostname sni:{}", sni);
        Ok(sni.to_string())
    }

    pub fn close(&self) {
        unsafe { cglue::gnutls_deinit(self.xsession) };
    }

    #[track_caller]
    pub fn check_pending(&self) -> bool {
        let status = unsafe { cglue::gnutls_record_check_pending(self.xsession) };
        if status == 0 {
            false
        } else {
            true
        }
    }

    #[track_caller]
    pub fn recv(&self, buffer: &mut [u8]) -> Result<usize, AfbError> {
        let ret = unsafe {
            cglue::gnutls_record_recv(
                self.xsession,
                buffer.as_mut_ptr() as *mut raw::c_void,
                buffer.len(),
            )
        };

        if unsafe { cglue::gnutls_error_is_fatal(ret as i32) } < 0 {
            // let try to rehandshake
            let response = if ret == cglue::C_GNUTLS_E_REHANDSHAKE as isize {
                self.client_handshake()?;
                Ok(0)
            } else {
                // move gnutls error to rust &str
                let cerror = unsafe { CStr::from_ptr(cglue::gnutls_strerror(ret as i32)) };
                let error = cerror.to_str().unwrap();
                afb_error!("gtls-session-recv", "error:{}", error)
            };
            return response;
        }

        Ok(ret as usize)
    }

    #[track_caller]
    pub fn send(&self, buffer: &[u8]) -> Result<usize, AfbError> {
        let ret = unsafe {
            cglue::gnutls_record_send(
                self.xsession,
                buffer.as_ptr() as *mut raw::c_void,
                buffer.len(),
            )
        };

        if unsafe { cglue::gnutls_error_is_fatal(ret as i32) } < 0 {
            // let try to rehandshake
            let response = if ret == cglue::C_GNUTLS_E_REHANDSHAKE as isize {
                self.client_handshake()?;
                Ok(0)
            } else {
                // move gnutls error to rust &str
                let cerror = unsafe { CStr::from_ptr(cglue::gnutls_strerror(ret as i32)) };
                let error = cerror.to_str().unwrap();
                afb_error!("gtls-session-send", "error:{}", error)
            };
            return response;
        }

        Ok(ret as usize)
    }

    pub fn get_version(&self) -> GnuTlsVersion {
        let version = unsafe { cglue::gnutls_protocol_get_version(self.xsession) };
        GnuTlsVersion::from_u32(version)
    }

    #[track_caller]
    pub fn client_handshake(&self) -> Result<(), AfbError> {
        let status = unsafe { cglue::gnutls_handshake(self.xsession) };
        if status < 0 {
            return afb_error!(
                "gtls-session-handskake",
                "fail tls handshake error:{}",
                gtls_perror(status)
            );
        }
        Ok(())
    }
    #[allow(dead_code)]
    #[track_caller]
    pub fn set_secure(&self) -> &Self {
        unsafe {
            cglue::gnutls_session_set_ptr(self.xsession, self as *const _ as *mut raw::c_void);
            cglue::gnutls_certificate_set_verify_function(self.xcred, Some(client_certificate_cb));
            cglue::gnutls_certificate_set_verify_flags(
                self.xcred,
                cglue::gnutls_certificate_verify_flags_GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT,
            );
        }
        self
    }
}

#[derive(Clone)]
pub struct GnuTlsConfig {
    version: String,
    tls_psk: Option<&'static str>,
    priority: CString,
    xcred: cglue::gnutls_certificate_credentials_t,
    authent: cglue::gnutls_credentials_type_t,
    logger: Rc<TlsKeyLogger>,
}
impl GnuTlsConfig {
    pub fn new(
        cert_path: &str,
        key_path: &str,
        key_pin: Option<&str>,
        ca_trust: Option<&str>,
        tls_psk: Option<&'static str>,
        psk_log: Option<&'static str>,
        tls_verbosity: i32,
        tls_proto: Option<&'static str>,
    ) -> Result<Self, AfbError> {
        //const GNU_TLS2_PRIO: &str = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.3";
        const GNU_TLS_PROTO: &str =
            "SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128:+PSK:+DHE-PSK";
        const GNU_TLS_MIN_VER: &str = "3.4.6";

        let glutls_version = match CString::new(GNU_TLS_MIN_VER) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!(
                    "gtls-init-string",
                    "fail to import iface:{}",
                    GNU_TLS_MIN_VER
                )
            }
        };
        let version = match unsafe { cglue::gnutls_check_version(glutls_version.as_ptr()).as_ref() }
        {
            Some(value) => unsafe { CStr::from_ptr(value).to_str().unwrap().to_string() },
            None => {
                return afb_error!(
                    "gtls-init-version",
                    "invalid glutls version expect minimum:{}",
                    GNU_TLS_MIN_VER
                )
            }
        };

        let glutls_key = match CString::new(key_path) {
            Ok(value) => value,
            Err(_) => return afb_error!("gtls-client-key", "fail to import key:{}", key_path),
        };

        let glutls_cert = match CString::new(cert_path) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!("gtls-server-cert", "fail to import tls_certs:{}", cert_path)
            }
        };

        let glutls_pin = match key_pin {
            None => None,
            Some(pin) => match CString::new(pin) {
                Ok(value) => Some(value),
                Err(_) => return afb_error!("gtls-server-key", "fail to import tls_pin:{}", pin),
            },
        };

        let xcred = unsafe {
            let mut cred = mem::MaybeUninit::<cglue::gnutls_certificate_credentials_t>::uninit();
            let status = cglue::gnutls_certificate_allocate_credentials(cred.as_mut_ptr());
            let cred = cred.assume_init();
            if status < 0 {
                return afb_error!(
                    "gtls-config-credential",
                    "file to initialise session keyfile:{} error:{}",
                    key_path,
                    gtls_perror(status)
                );
            }
            cred
        };

        let status = unsafe {
            match ca_trust {
                None => 0,
                Some(ca) => cglue::gnutls_certificate_set_x509_trust_dir(
                    xcred,
                    ca.as_ptr() as *mut raw::c_char,
                    cglue::C_GNUTLS_X509_FMT_PEM,
                ),
            }
        };

        if status <= 0 {
            return afb_error!(
                "gtls-config-ca",
                "invalid glutls key/certification ca_path:{} error:{}",
                cert_path,
                gtls_perror(status)
            );
        }

        let status = unsafe {
            match glutls_pin {
                None => cglue::gnutls_certificate_set_x509_key_file(
                    xcred,
                    glutls_cert.as_ptr(),
                    glutls_key.as_ptr(),
                    cglue::C_GNUTLS_X509_FMT_PEM,
                ),
                Some(pin) => cglue::gnutls_certificate_set_x509_key_file2(
                    xcred,
                    glutls_cert.as_ptr(),
                    glutls_key.as_ptr(),
                    cglue::C_GNUTLS_X509_FMT_PEM,
                    pin.as_ptr(),
                    cglue::gnutls_pkcs_encrypt_flags_t_GNUTLS_PKCS_PLAIN,
                ),
            }
        };

        if status < 0 {
            return afb_error!(
                "gtls-config-cert",
                "invalid glutls key/certification cert:{} key:{} error:{}",
                cert_path,
                key_path,
                gtls_perror(status)
            );
        }

        // If tls_psk then use TLS-1.3 otherwise use TLS-1.2
        let authent = match tls_psk {
            None => cglue::gnutls_credentials_type_t_GNUTLS_CRD_CERTIFICATE,
            Some(psk) => {
                afb_log_msg!(
                    Warning,
                    None,
                    "{{PRE_SHARED_KEY(for-test-only) psk:'{}'}}",
                    psk
                );
                unsafe {
                    let mut psk_cred =
                        mem::MaybeUninit::<cglue::gnutls_psk_server_credentials_t>::uninit();
                    let status =
                        cglue::gnutls_psk_allocate_server_credentials(psk_cred.as_mut_ptr());
                    let psk_cred = psk_cred.assume_init();
                    if status != 0 {
                        return afb_error!(
                            "gtls-config-psk",
                            "fail to register psk_server_credentials error:{}",
                            gtls_perror(status)
                        );
                    };

                    cglue::gnutls_psk_set_server_credentials_function(
                        psk_cred,
                        Some(pre_share_key_cb),
                    );
                };
                cglue::gnutls_credentials_type_t_GNUTLS_CRD_PSK
            }
        };

        // If tls_psk then use TLS-1.3 otherwise use TLS-1.2
        let priority = match tls_proto {
            Some(value) => value,
            None => GNU_TLS_PROTO,
        };

        if tls_verbosity > 0 {
            unsafe {
                cglue::gnutls_global_set_log_level(tls_verbosity);
                cglue::gnutls_global_set_log_function(Some(verbosity_log_cb));
            };
        }

        let config = GnuTlsConfig {
            version,
            tls_psk,
            xcred,
            authent,
            priority: CString::new(priority).unwrap(),
            logger: Rc::new(TlsKeyLogger::new(psk_log)?),
        };
        Ok(config)
    }

    pub fn get_key(&self, index: u32) -> Result<cglue::gnutls_x509_privkey_t, AfbError> {
        let key = unsafe {
            let mut buffer = mem::MaybeUninit::<cglue::gnutls_x509_privkey_t>::uninit();
            let status =
                cglue::gnutls_certificate_get_x509_key(self.xcred, index, buffer.as_mut_ptr());
            if status < 0 {
                return afb_error!(
                    "gtls-session-credential",
                    "file to retreive private key from config index:{}, error:{}",
                    index,
                    gtls_perror(status)
                );
            }
            buffer.assume_init()
        };
        Ok(key)
    }
    pub fn get_cert(&self, index: u32) -> Result<(*mut cglue::gnutls_x509_crt_t, u32), AfbError> {
        let list = unsafe {
            let mut buffer = mem::MaybeUninit::<*mut cglue::gnutls_x509_crt_t>::uninit();
            let count = 0;
            let status = cglue::gnutls_certificate_get_x509_crt(
                self.xcred,
                index,
                buffer.as_mut_ptr(),
                &count as *const _ as *mut u32,
            );
            if status < 0 {
                return afb_error!(
                    "gtls-session-credential",
                    "file to retreive cert from config index:{}, error:{}",
                    index,
                    gtls_perror(status)
                );
            }
            (buffer.assume_init(), count)
        };
        Ok(list)
    }

    pub fn get_version(&self) -> String {
        self.version.clone()
    }

    pub fn set_verbosity(&self, level: i32) {
        unsafe { cglue::gnutls_global_set_log_level(level) };
    }
}
