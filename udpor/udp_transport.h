
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



#ifndef UDP_TRANSPORT_H
#define UDP_TRANSPORT_H


#include <stdint.h>
//#include <netinet/ip.h>
#include <sys/types.h>
//#include <endian.h>

#ifndef __LITTLE_ENDIAN
#ifndef __BIG_ENDIAN   

#define	__LITTLE_ENDIAN	1234
#define	__BIG_ENDIAN	4321

#if defined(__i386__) || defined(__x86_64__) || defined(__ia64__)
#define __BYTE_ORDER		__LITTLE_ENDIAN
#define __FLOAT_WORD_ORDER	__BYTE_ORDER
#endif

#if defined(__ppc__) || defined(__ppc64__)
#define __BYTE_ORDER            __BIG_ENDIAN
#define __FLOAT_WORD_ORDER      __BYTE_ORDER
#endif


#endif
#endif


/*defne 64 bit swaps*/
#define __BSWAP64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)                                   \
      | (((x) & 0x00ff000000000000ull) >> 40)                                 \
      | (((x) & 0x0000ff0000000000ull) >> 24)                                 \
      | (((x) & 0x000000ff00000000ull) >> 8)                                  \
      | (((x) & 0x00000000ff000000ull) << 8)                                  \
      | (((x) & 0x0000000000ff0000ull) << 24)                                 \
      | (((x) & 0x000000000000ff00ull) << 40)                                 \
      | (((x) & 0x00000000000000ffull) << 56))



#ifndef ntohll
#ifndef htonll
  #if __BYTE_ORDER == __LITTLE_ENDIAN
    # define ntohll(x)       __BSWAP64 (x)
    # define htonll(x)       __BSWAP64 (x)
  #elif __BYTE_ORDER == __BIG_ENDIAN
    # define ntohll(x)       (x)
    # define htonll(x)       (x)
  #else
    # error "Please fix <bits/endian.h>"
  #endif
#endif
#endif



typedef union{
   uint8_t       as_byte[8];
   unsigned char as_uchar[8];
   uint64_t      as_uint64;
}multi64_t;

typedef union{
   uint8_t       as_byte[7];
   unsigned char as_uchar[7]; 
}multi56_t;

#define OR_CELL_VERSION 1

/*Define packing data structures*/
typedef struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int size:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int size:4;
#else
# error "Please fix <bits/endian.h>"
#endif
   uint8_t  circuit_id_high;
   uint16_t circuit_id_low;
   uint32_t reserved;  //This is to align data to 16 byte boundary
                       //so that a 128 bit block cipher aligns with
                       //the end of the init vector!
   multi64_t init_vector;
   multi56_t checksum;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int command_status:4;
    unsigned int command:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int command:4;
    unsigned int command_status:4;
#else
# error "Please fix <bits/endian.h>"
#endif
}cell_header_t;

/*
typedef struct {
   uint16_t stream_id;
   uint16_t length;  
   uint8_t  relay_command;
}relay_header_t;
*/

#define STATUS_REQUEST 0
#define STATUS_OK      1    //condition exists
#define STATUS_ACK     2    // I am processing your request
#define STATUS_LATER   3    // I cant process your request now
#define STATUS_DENIED  4    // I cannot process your request

#define COMMAND_PADDING       0
#define COMMAND_CONNECT       1  //assign
                                 // me a new circuit, connecting to some host.
#define COMMAND_CREATE        2  // Lets exchange KEY INFO
#define COMMAND_RELAY_COMMAND 3  // This cell contians another cell to
                                 // be relayed
#define COMMAND_DESTROY       4  //Destroy this circuit!
#define COMMAND_STREAM_DATA   5  //This contains stream DATA! 

#define MAX_DH_PUBLIC_SIZE 256
#define MAX_RSA_KEY_SIZE 256

#define DH_HELLO_EXTRA_TYPE_NONE 0
#define DH_HELLO_EXTRA_TYPE_SHA  1
#define DH_PKI_ENCRYPTED_LEN     12

typedef struct{
   uint16_t key_size      __attribute((packed));
   uint16_t encrypted_len __attribute((packed)); //is variable due to padding?
   uint8_t extra_type;
   uint8_t extra_len;
   unsigned char pub_key[MAX_DH_PUBLIC_SIZE];
}dh_hello_t;

typedef struct{
   uint16_t addr_type     __attribute((packed));
   uint16_t port          __attribute((packed));
   uint32_t ipv4_addr     __attribute((packed));
   unsigned char pub_key[MAX_RSA_KEY_SIZE];
}connect_to_t;

typedef struct{
   uint16_t stream_id     __attribute((packed));
   uint16_t opt_length    __attribute((packed));
}stream_header_t;

typedef struct{
   uint8_t  proto;        
   uint8_t  reserve;       
   uint16_t dst_port      __attribute((packed));
}stream_extra_header_t;

typedef struct{
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
    uint16_t urg_ptr;

}quasi_tcp_header_t;


#endif



