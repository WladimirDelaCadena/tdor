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


#ifndef UTIL_H
#define UTIL_H
#include <sys/time.h>

typedef struct{
   struct timeval last_time;
   uint32_t size; //in bytes
   uint32_t current_size; 
   uint32_t kbps; //in bits per second
   uint32_t threshold; //in bytes of the queue
}bw_queue_state_t;


int fprint_hex(FILE *stream,const unsigned char *data,const uint32_t datalen);
int fprint_or_stream(FILE *stream,const or_stream_t *or_stream);
int queue_drop_packet(const uint32_t packet_size,const struct timeval *current_time,bw_queue_state_t *queue );
uint32_t guess_ipv4_addr();
int fprint_pub_conf(FILE *stream,const global_conf_t *conf,const bw_queue_state_t *queue);
int rsa_in_place_decrypt(RSA *rsa,unsigned char *in_out,uint16_t in_len,uint16_t max_out_len);
int rsa_in_place_encrypt(RSA *rsa,unsigned char *in_out,uint16_t in_len,uint16_t max_out_len);


#endif

