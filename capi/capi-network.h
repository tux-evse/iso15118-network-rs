/*
 * Copyright 2023 - 2022 Pionix GmbH, IoT.bzh and Contributors to EVerest
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
 * Interface file extracted from: https://github.com/EVerest/libiso15118
 * Generate Rust structures for ISO15118-2/20 messages.
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

const ushort C_AF_INET6 = AF_INET6;
const int C_SOCK_DGRAM = SOCK_DGRAM;
const int C_IPPROTO_UDP = IPPROTO_UDP;
const int C_SOL_SOCKET = SOL_SOCKET;
const int C_SO_REUSEPORT = SO_REUSEPORT;
const int C_IPPROTO_IPV6= IPPROTO_IPV6;
const int C_IPV6_JOIN_GROUP= IPV6_JOIN_GROUP;
const int C_IP_PKTINFO= IP_PKTINFO;
const int C_IP_MULTICAST_LOOP= IP_MULTICAST_LOOP;

const int C_SIOCGIFINDEX= SIOCGIFINDEX;
const int C_SIOCGIFNAME= SIOCGIFNAME;
const int C_BINDTODEVICE= SO_BINDTODEVICE;


const size_t C_IFNAMSIZ= IFNAMSIZ;
const size_t C_INET6_ADDRSTRLEN = INET6_ADDRSTRLEN;
struct sockaddr_in6 mockv6;
const size_t C_INET6_ADDR_LEN= sizeof (mockv6.sin6_addr);
const size_t C_INET6_PORT_LEN= sizeof (mockv6.sin6_port);

const int C_GNUTLS_E_CERTIFICATE_ERROR=GNUTLS_E_CERTIFICATE_ERROR;
const uint C_GNUTLS_X509_FMT_PEM= GNUTLS_X509_FMT_PEM;
const uint C_GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT= GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT;
const uint C_GNUTLS_CERT_INVALID=GNUTLS_CERT_INVALID;
const uint C_GNUTLS_CERT_SIGNER_NOT_FOUND=GNUTLS_CERT_SIGNER_NOT_FOUND;
const uint C_GNUTLS_CERT_REVOKED=GNUTLS_CERT_REVOKED;
const uint C_GNUTLS_CERT_EXPIRED=GNUTLS_CERT_EXPIRED;
const uint C_GNUTLS_CERT_NOT_ACTIVATED=GNUTLS_CERT_NOT_ACTIVATED;
const uint C_GNUTLS_CRT_X509=GNUTLS_CRT_X509;
const uint C_GNUTLS_X509_FMT_DER= GNUTLS_X509_FMT_DER;
const int C_GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT=GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT;
const int C_GNUTLS_E_INTERRUPTED=GNUTLS_E_INTERRUPTED;
const int C_GNUTLS_E_REHANDSHAKE=GNUTLS_E_REHANDSHAKE;
const int C_GNUTLS_E_AGAIN=GNUTLS_E_AGAIN;
const uint C_GNUTLS_NAME_DNS=GNUTLS_NAME_DNS;
