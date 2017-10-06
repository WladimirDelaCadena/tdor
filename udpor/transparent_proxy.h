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

#ifndef TRANSPARENT_PROXY_H
#define TRANSPARENT_PROXY_H

#include "socks.h"

int tcp_packet_transparent_proxy_handle_forward(or_stream_t *stream, const struct ip *ip_header,struct tcphdr *tcp);
int tcp_packet_transparent_proxy_handle_reverse(or_stream_t *stream, unsigned const char *stream_payload);

#endif

