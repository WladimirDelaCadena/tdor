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

#ifndef LINK_CONN_H
#define LINK_CONN_H

/*
This file should be renamed as or_conn handler

*/

#include <stdio.h>
#include <openssl/dh.h>

#define MAX_LINK_PACKET_SIZE 2048
#define LINK_VERSION 1

#define CONN_STATE_NEW         0
#define CONN_STATE_CAPA_SENT   1
#define CONN_STATE_CAPA_RECV   2
#define CONN_STATE_ESTABLISHED 3
#define CONN_STATE_DH_SENT     4
#define CONN_STATE_DH_REPSENT  5
#define CONN_STATE DEAD        6

#define LINK_PK_TYPE_DUMMY 0
#define LINK_PK_TYPE_CAPAHELLO 1
#define LINK_PK_TYPE_CAPAHELLOREPLY 2
#define LINK_PK_TYPE_DH_HELLO 3
#define LINK_PK_TYPE_DH_HELLO_REPLY 4
#define LINK_PK_TYPE_DATA 5
#define LINK_PK_TYPE_CON_CLOSE 6
#define LINK_PK_TYPE_ECHO_REQUEST 7

//transport level
typedef struct {
   uint8_t  version   ;
   uint8_t  type      ;
   uint16_t length    __attribute__((packed)) ;  //including the header
   uint64_t iv        __attribute__((packed)) ; 
   uint64_t checksum  __attribute__((packed)) ;
}link_header_t ;

typedef struct{
   uint8_t  version   ;
   uint32_t sym_alg   __attribute__((packed));
   uint32_t pub_type  __attribute__((packed));
   uint32_t magic     __attribute__((packed));
}link_capabilities_t;

typedef struct{
   uint16_t key_size   __attribute__((packed));
   uint16_t hash_size  __attribute__((packed));
   unsigned char pubkey[256];
   unsigned char hash[256];
}link_dh_t;

int send_link_state_packet(or_conn_t *conn,uint32_t type);
int send_link_data_packet(or_conn_t *conn,unsigned char *data,uint16_t datalen); 

int handle_link_packet(unsigned char *data,size_t size,uint32_t remote_ip,uint16_t port);

#endif
