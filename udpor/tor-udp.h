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


#ifndef TOR_UDP_H
#define TOR_UDP_H
/*
This header contains common data structs for this implementaiton
of udp tor. It is independent of  a protocol specification.
*/


#include <stdint.h>
//#include <endian.h>
//#include "circuit_crypto.h"
#include <dnet.h>
#include <openssl/rsa.h>
#include "dh_params.h"

#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>

#include <sys/time.h>
//#include <mcheck.h>

#ifndef VERBOSE
//#define VERBOSE
#endif

//#include "internal_db.h"

//struct conn_db_st;
//struct circuit_db;
#define MAX_RSA_EXP_SIZE 8
#define MAX_RSA_MOD_SIZE 512 

typedef struct {
   uint16_t e_size;
   uint16_t n_size;
   unsigned char e[MAX_RSA_EXP_SIZE];
   unsigned char n[MAX_RSA_MOD_SIZE];
   RSA *rsa;
}router_rsa_t;

typedef struct{
  uint32_t ip;
  uint16_t udp_port;
  uint16_t tcp_port;
  uint8_t  is_exit;
  uint32_t bw; 
  router_rsa_t rsa;
} router_data_t;

/*Configuration global*/
typedef struct{
   uint8_t is_exit;
   uint8_t is_client;
   int tun_fd;
   int bind_fd;
   tun_t *tun;
   uint32_t advertised_ipv4;
   uint32_t bind_ipv4;
   //char *src="10.8.0.1/28";
   //char *dst="10.8.0.2/28";
   uint16_t bind_port;
   char net_addr[20]; //for the tun interface 
   uint32_t default_rem_ip;
   struct timeval current_time;
   RSA *rsa_key;
}global_conf_t;


/*define internal data structs*/
typedef struct {
   int fd;
}no_crypto_single_sock_conn_t;

typedef struct {
   int fd;
}no_crypto_multi_sock_conn_t;

#define CV_ALG_NONE  0
#define CV_ALG_BF    1
#define CV_ALG_AES   2
#define CV_HASH_NONE 0
#define CV_HASH_SHA  1

typedef struct {
   int fd;
   DH *dh;
   unsigned char key[256]; //this can be smaller!
   uint16_t key_size;
   uint32_t algo;
   uint8_t hash_type;
   //RSA *rsa; 
}cv_link_conn_t;


typedef union crypto_conn_t_tag{
  no_crypto_single_sock_conn_t as_single_conn;
  no_crypto_multi_sock_conn_t as_multi_conn;
  cv_link_conn_t as_link;
}crypto_conn_t;

//#define OR_CONN_STATE 
//#define CONN_STATE_ESTABLISHED 1
//#define CONN_STATE_DH_SENT     2
//#define CONN_STATE_DH_REPSENT  3
//#define CONN_STATE DEAD        4
//#define OR_CONN_STATE_NEW          0
//#define OR_CONN_STATE_INITIALIZING 1
//#define OR_CONN_STATE_ESTABLISHED  2
//#define OR_CONN_STATE_DEAD         3


typedef struct{
   uint64_t packets_in;
   uint64_t packets_processed;
   uint64_t packets_out;
   uint64_t local_iv;
   uint32_t remote_ip;
   uint32_t remote_port;
   uint8_t  state;
   uint8_t  initiator;
   uint32_t magic;
   uint32_t last_recv_sec;
   uint32_t last_sent_sec;
   crypto_conn_t crypto_conn;
   void *circuit_db;
   RSA *rsa;
}or_conn_t;

#define OR_CRYPTO_ALG_NONE     0
#define OR_CRYPTO_ALG_AES      1
#define OR_CRYPTO_ALG_BLOWFISH 2
typedef struct{
   AES_KEY encrypt;
   AES_KEY decrypt;
}AES_KEY_PAIR;


//dont forget to initialize!!
typedef union {
//typedef struct{
  //AES_KEY_PAIR  aes;
  //BF_KEY  bf;
  unsigned char    key[128];
}circuit_crypto_sym_key_t;


typedef struct {
  uint16_t alg;
  uint16_t key_size;
  circuit_crypto_sym_key_t key;
  DH *dh;
  RSA *rsa;
}circuit_crypto_conn_t;




#define OR_CIRCUIT_STATE_NEW             0
#define OR_CIRCUIT_STATE_DH_HELLO_SENT   1
#define OR_CIRCUIT_STATE_DH_HELLO_RECV   2
#define OR_CIRCUIT_STATE_ESTABLISHED     3
#define OR_CIRCUIT_STATE_DEAD            4
#define OR_CIRCUIT_STATE_CONNECTING      5
#define OR_CIRCUIT_STATE_RELAY_ONLY      6

#define MAX_CLIENT_CIRCUIT_HOPS 4

struct or_circuit_st{
   or_conn_t *or_conn;
   uint8_t num_cryptos;
   //circuit_crypto_conn_t *sym_crypto_info;
   time_t start_time;
   time_t last_time;
   uint8_t state[MAX_CLIENT_CIRCUIT_HOPS];
   uint8_t local;
   uint8_t max_level;
   uint32_t circuit_id;
   uint32_t packet_count[MAX_CLIENT_CIRCUIT_HOPS]; //this might need to be 
   uint64_t isv_seed;
   struct or_circuit_st *related_circuit;
   //circuit_crypto_conn_t sym_crypto_info[MAX_CLIENT_CIRCUIT_HOPS];
   //Next struct HAS to be ad the end... bad coding!
   circuit_crypto_conn_t *sym_crypto_info;
};

typedef struct or_circuit_st or_circuit_t; 

#define OR_STREAM_PROXY_STATE_NONE         0
#define OR_STREAM_PROXY_STATE_NEW          1
#define OR_STREAM_PROXY_STATE_SYN_ACK_RECV 2
#define OR_STREAM_PROXY_STATE_READY        3

#define OR_STREAM_ACK_COPY_SIZE 12

typedef struct{
   or_circuit_t *parent_circuit;
   or_circuit_t *secondary_circuit;
   uint32_t stream_id;
   uint8_t protocol;
   uint16_t local_port;
   uint16_t remote_port;
   uint32_t local_ip;
   uint32_t remote_ip;
   time_t last_time;
   uint32_t out_packets;

   //the next are for tcp scrubbing
   uint32_t seq_add;   //add this to all forward sq
                       //subtract this all reverse acks (including sack!)
   uint8_t  win_comp;  

   // the next is for transparent proxying!
   uint8_t proxy_state;
   uint8_t synack_opt_bytes;
   uint8_t synack_opt_data[OR_STREAM_ACK_COPY_SIZE];
   

}or_stream_t;


#endif

