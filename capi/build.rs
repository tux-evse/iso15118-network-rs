/*
 * Copyright (C) 2015-2023 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Redpesk interface code/config use MIT License and can be freely copy/modified even within proprietary code
 * License: $RP_BEGIN_LICENSE$ SPDX:MIT https://opensource.org/licenses/MIT $RP_END_LICENSE$
 *
*/
use std::env;

fn main() {
    // invalidate the built crate whenever the wrapper changes
    println!("cargo:rustc-link-search=/usr/local/lib64");
    println!("cargo:rustc-link-arg=-lgnutls");

    if let Ok(value) = env::var("CARGO_TARGET_DIR") {
        if let Ok(profile) = env::var("PROFILE") {
            println!("cargo:rustc-link-search=crate={}{}", value, profile);
        }
    }
    let header = "
    // -----------------------------------------------------------------------
    //         <- private 'lib-iso15118' Rust/C unsafe binding ->
    // -----------------------------------------------------------------------
    //   Do not exit this file it will be regenerated automatically by cargo.
    //   Check:
    //     - build.rs for C/Rust glue options
    //     - src/capi/capi-network.h for C prototype inputs
    // -----------------------------------------------------------------------
    ";
    println!("cargo:rerun-if-changed=capi/capi-network.h");
    let libcapi = bindgen::Builder::default()
        .header("capi/capi-network.h") // Chargebyte C prototype wrapper input
        .raw_line(header)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .derive_debug(false)
        .layout_tests(false)
        .allowlist_function("__errno_location")
        .allowlist_function("errno")
        .allowlist_function("strerror_r")
        .allowlist_var("C_.*")
        .allowlist_type("sockaddr_in6")
        .allowlist_type("ipv6_mreq")
        .allowlist_type("ifreq")
        .allowlist_function("bind")
        .allowlist_function("malloc")
        .allowlist_function("socket")
        .allowlist_function("setsockopt")
        .allowlist_function("close")
        .allowlist_function("ioctl")
        .allowlist_function("recvfrom")
        .allowlist_function("sendto")
        .allowlist_function("inet_ntop")
        .allowlist_function("hton.*")
        .allowlist_function("ntoh.*")
        .allowlist_function(".*ifaddrs")
        .allowlist_function("gnutls_.*")
        .allowlist_type("gnutls_.*")
        .generate()
        .expect("Unable to generate _capi-network");

    libcapi
        .write_to_file("capi/_capi-network.rs")
        .expect("Couldn't write _capi-network.rs!");

}
