/*
**  (C) 2007-2008 Camilo Viecco.  All rights reserved.
**
**  This file is part of Tdor, and is subject to the license terms in the
**  LICENSE file, found in the top level directory of this distribution. If you
**  did not receive the LICENSE file with this file, you may obtain it by
**  contacting the authors listed above. No part of Tdor, including this file,
**  may be copied, modified, propagated, or distributed except according to the
**  terms described in the LICENSE file.
*/

#ifndef SOCKS_H
#define SOCKS_H

#include <stdint.h>

typedef struct {
   uint8_t version;
   uint8_t command;
   uint16_t port;
   uint32_t dest;
}socks4_header_t;

typedef struct {
   uint8_t version;
   uint8_t nmethods;
   uint8_t methods;
}socks5_client_hello_t;

typedef struct {
   uint8_t version;
   uint8_t methods;
}socks5_server_hello_t;


#endif
