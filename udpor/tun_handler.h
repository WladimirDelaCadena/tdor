
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


#ifndef TUN_HANDLER_H
#define TUN_HANDLER_H

#include "config.h"
#include <sys/types.h>
#include <stdint.h>

#include <dnet.h>
#include <netinet/ip.h>
//#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/ip_icmp.h>
#include "tor-udp.h"

#ifndef HAVE_STRUCT_ICMPHDR_TYPE
struct icmphdr
{
  uint8_t type;                /* message type */
  uint8_t code;                /* type sub-code */
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t id;
      uint16_t sequence;
    } echo;                     /* echo datagram */
    uint32_t   gateway;        /* gateway address */

    struct
    {
      uint16_t unused;
      uint16_t mtu;
    } frag;                     /* path mtu discovery */

  } un;
};
#endif

struct tcphdr
  {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

#define MAX_TUN_PACKET 2048

int send_output_ip_packet(or_stream_t *stream,unsigned const char *in_stream );
int handle_tunnel_packet(tun_t *tun);
int build_tcp_stream_payload(or_stream_t *stream, unsigned char *inpacket, unsigned char *out);
#endif
