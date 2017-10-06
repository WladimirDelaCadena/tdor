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

#include <stdio.h>
#include "tor-udp.h"
#include <unistd.h>
#include <string.h>
#include "dh_params.h"
#include <stdlib.h>
#include "link_conn.h"
#include "internal_db.h"
#include "cell_handler.h"
#include "udp_transport.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include "util.h"
#include <sys/socket.h>
#include <errno.h>
#include <assert.h>

/*
Last rcv sec is updated when while established padding or data arrives!

*/

//#define VERBOSE
//#define DEBUG_LINK_CONN

extern conn_db_t conn_db;
extern global_conf_t global_conf;
extern bw_queue_state_t output_queue;

int link_encrypt_sign_payload(or_conn_t *conn,unsigned char *packet,uint32_t length){
   //lenght it the TOTAL size of the packet

   //hash and then encrypt!
   uint8_t hashval[256];
   link_header_t *header;
   static uint64_t iv=0;
   int enc_len;
   AES_KEY aes_key;
   unsigned char iv_tmp[64];
   unsigned char buffer[MAX_LINK_PACKET_SIZE];
  
   //since the encryption must be a multiple of 16... modify stuff
   enc_len=((length-sizeof(link_header_t)+15)>>4)<<4;
   length=enc_len+sizeof(link_header_t);

   if(NULL==conn){fprintf(stderr,"link_encrypt payload: null conn!\n ");exit(1);}
   iv++;

   //should this calm valgrind?
   memset(buffer,0x00,64);


   header=(link_header_t *)packet;
   header->iv=htonll(iv);
   header->length=htons(length);

   switch(conn->crypto_conn.as_link.hash_type){
     case CV_HASH_NONE:
         memset(hashval,0x00,sizeof(uint64_t));
         break;
     case CV_HASH_SHA:
         SHA1((unsigned char *)packet+sizeof(link_header_t),length-sizeof(link_header_t),
                                           hashval);
         break;
   }
 
   memcpy(&(header->checksum),hashval,sizeof(uint64_t));

   switch(conn->crypto_conn.as_link.algo){
      case CV_ALG_NONE:
          return length;
      case CV_ALG_AES:
           memset(iv_tmp,0x00,64);
           memcpy(iv_tmp,&(header->iv),8);//copy iv into iv_tmp
           AES_set_encrypt_key(conn->crypto_conn.as_link.key, 128,&aes_key);
#ifdef DEBUG_LINK_CONN
           fprintf(stderr,"link enc enclen=%d iv=\n",enc_len);
           fprint_hex(stderr,(char *)(&header->iv), 8);
           fprintf(stderr,"\n");
         
           fprintf(stderr,"pre=\n");
           fprint_hex(stderr,packet+sizeof(link_header_t), 24);
           fprintf(stderr,"\n");
#endif
           AES_cbc_encrypt(packet+sizeof(link_header_t),buffer,
                                   enc_len,&aes_key,
                                   iv_tmp,AES_ENCRYPT);

           //now overwrite
           memcpy(packet+sizeof(link_header_t),buffer,enc_len); 
#ifdef DEBUG_LINK_CONN
           fprintf(stderr,"post=\n");
           fprint_hex(stderr,packet+sizeof(link_header_t), 24);
           fprintf(stderr,"\n");
#endif
           return length;
           
      default:
          fprintf(stderr,"Alg unkown/not implemented: alg=%d\n",
                         conn->crypto_conn.as_link.algo);
          exit(1);
   }
   
   return 0;
};

int link_decrypt_verify_payload(or_conn_t *conn,unsigned char *packet,uint32_t length){
   //length is the actual lenght of the 

   //now decrypt and then verify
   uint8_t hashval[256];
   uint64_t inhash,comphash;
   link_header_t *header;
   int declen;
   int validlen=0;
   AES_KEY aes_key;
   unsigned char iv_tmp[64];
   unsigned char buffer[MAX_LINK_PACKET_SIZE];


   if(NULL==conn){fprintf(stderr,"link_decrypt payload: null conn!\n ");exit(1);}

   //saniti check
   assert(length+15<MAX_LINK_PACKET_SIZE);

   header=(link_header_t *)packet;
   if(length<ntohs(header->length)){
      fprintf(stderr,"invalid packet lenght! got %d\n",header->length);
   }
   length=ntohs(header->length);

   declen=ntohs(header->length)-sizeof(link_header_t);

   //if not established try hash without crypto first!
   if(CONN_STATE_ESTABLISHED!=conn->state){
 
     switch(conn->crypto_conn.as_link.hash_type){
        case CV_HASH_NONE:
            //hash should be empty!;
            memcpy(&inhash,&header->checksum,sizeof(uint64_t));
            if(inhash==0){
               validlen=length;
            }
            else{
               validlen=0;
            }
            break;
        case CV_HASH_SHA:
            SHA1(packet+sizeof(link_header_t),length-sizeof(link_header_t),
                                           hashval);
            memcpy(&inhash,&header->checksum,sizeof(uint64_t));
            memcpy(&comphash,hashval,sizeof(uint64_t));
            if(inhash==comphash){
               validlen=length;
            }
            else{
            validlen=0;
            }

            break;
        }
      if(validlen!=0)
         return validlen;

   }

   switch(conn->crypto_conn.as_link.algo){
      case CV_ALG_NONE:
          //declen=length;
          break;
      case CV_ALG_AES:
          AES_set_decrypt_key(conn->crypto_conn.as_link.key, 128,&aes_key);
           memset(iv_tmp,0x00,64);
           memcpy(iv_tmp,&(header->iv),8);//copy iv into iv_tmp   
#ifdef DEBUG_LINK_CONN
           fprintf(stderr,"link dec declen=%d iv=\n",declen);
           fprint_hex(stderr,(char *)(&header->iv), 8);
           fprintf(stderr,"\n");

           fprintf(stderr,"pre=\n");
           fprint_hex(stderr,packet+sizeof(link_header_t), 24);
           fprintf(stderr,"\n");
#endif     
          AES_cbc_encrypt(packet+sizeof(link_header_t),buffer,                                                           declen,&aes_key,
                                   iv_tmp,AES_DECRYPT);

#ifdef DEBUG_LINK_CONN
           fprintf(stderr,"post=\n");
           fprint_hex(stderr,buffer, 24);
           fprintf(stderr,"\n");
#endif


          //now overwrite
          memcpy(packet+sizeof(link_header_t),buffer,declen);
          //declen=length;
          break;
      default:
          fprintf(stderr,"Dec_link: Crpyto Alg unkown/not implemented: alg=%d\n",
                         conn->crypto_conn.as_link.algo);
          declen=0;
          //exit(1);
          return 0;
   }
   switch(conn->crypto_conn.as_link.hash_type){
     case CV_HASH_NONE:
         //hash should be empty!;
         memcpy(&inhash,&header->checksum,sizeof(uint64_t));
         if(inhash==0){
            validlen=length;
         }
         else{
            validlen=0;
         }
         break;
     case CV_HASH_SHA:
         SHA1(packet+sizeof(link_header_t),length-sizeof(link_header_t),
                                           hashval);
         memcpy(&inhash,&header->checksum,sizeof(uint64_t));
         memcpy(&comphash,hashval,sizeof(uint64_t));
         if(inhash==comphash){
            validlen=length;
         }
         else{
            validlen=0;
         }

         break;
   }

   return validlen;
};

int link_send_packet(or_conn_t *conn,unsigned char *packet,uint32_t length){
   struct sockaddr_in their_addr;
   ssize_t numbytes;
   int sockfd;
   int encrypted_len;
   int rvalue;   

   if(NULL==conn){fprintf(stderr,"link_send_packet: null conn!\n ");exit(1);}

   //encrypted_len
   encrypted_len=link_encrypt_sign_payload(conn,packet,length);


   //prepare 
   sockfd=conn->crypto_conn.as_link.fd;
   sockfd=global_conf.bind_fd;
   memset(&their_addr,0x00,sizeof(struct sockaddr_in));
   their_addr.sin_family = AF_INET;  
   their_addr.sin_port = htons(conn->remote_port); // short, network byte order
   //their_addr.sin_addr = *((struct in_addr *)he->h_addr);
   their_addr.sin_addr.s_addr=htonl(conn->remote_ip);
   //memset(their_addr.sin_zero, '\0', sizeof their_addr.sin_zero);


   rvalue=queue_drop_packet(length,&global_conf.current_time,&output_queue );
   if (rvalue<=0){
     return 0;
   }
   conn->last_sent_sec=global_conf.current_time.tv_sec;

   if ((numbytes = sendto(sockfd, packet, encrypted_len, 0,
             (struct sockaddr *)&their_addr, sizeof(struct sockaddr_in))) == -1) {
        perror("sendto");
        fprintf(stderr,"numbytes=%d enclen=%u len=%u,ip=%u port=%d\n",(int) numbytes,encrypted_len,length,conn->remote_ip,conn->remote_port);
        fprintf(stderr,"their_addr.sin_addr.s_addr=%u\n",their_addr.sin_addr.s_addr);
        exit(1);
   }
#ifdef DEBUG_LINK_CONN
   fprintf(stderr,"sennt %d bytes!\n",numbytes);
#endif
   return numbytes;
};

int send_link_state_packet(or_conn_t *conn,uint32_t type){
   unsigned char packet[1024];
   link_header_t *link_header;
   //dh_hello_t *dh_hello; 
   link_capabilities_t *capa_header;
   link_dh_t  *dh_hello;

   //initialize stuff
   packet[0]=0;


   //we first prepare the packet!
   link_header=(link_header_t *) packet;
   memset(link_header,0x00,sizeof(link_header_t)); 
   link_header->version=LINK_VERSION; 
   link_header->type=type;
   link_header->length=0; //just to be safe!
   switch(type){
      case LINK_PK_TYPE_DUMMY:
           switch (conn->state){
                case CONN_STATE_ESTABLISHED:
                   capa_header=(link_capabilities_t *)
                                (packet+sizeof(link_header_t));
                   capa_header->version=LINK_VERSION;
                   capa_header->sym_alg=0;
                   capa_header->pub_type=0;
                   capa_header->magic=0;
                   link_header->length=htons(sizeof(link_header_t)
                                       +sizeof(link_capabilities_t));
                   break;
                default:
                   fprintf(stderr,
                           "conn: asked to send capahello on bad state!\n");
                   return -1;
             }
           break;
      case LINK_PK_TYPE_CAPAHELLO:
           switch (conn->state){
                case CONN_STATE_NEW:
                case CONN_STATE_CAPA_SENT:
                   capa_header=(link_capabilities_t *) 
                                (packet+sizeof(link_header_t));
                   capa_header->version=LINK_VERSION;
                   capa_header->sym_alg=0;
                   capa_header->pub_type=0;
                   capa_header->magic=0;
                   link_header->length=htons(sizeof(link_header_t)
                                       +sizeof(link_capabilities_t));
                   conn->initiator=1;   
                   break;
                default:
                   fprintf(stderr,
                           "conn: asked to send capahello on bad state!\n");
                   return -1;
             }
           break;
      case LINK_PK_TYPE_CAPAHELLOREPLY:
           switch (conn->state){
                case CONN_STATE_NEW:
                case CONN_STATE_CAPA_RECV:
                   if(0==conn->magic){
                     conn->magic=rand();
                   }
                   capa_header=(link_capabilities_t *)                                                  (packet+sizeof(link_header_t));
                   capa_header->version=LINK_VERSION;
                   capa_header->sym_alg=0;
                   capa_header->pub_type=0;
                   capa_header->magic=conn->magic;
                   conn->initiator=0;
                   link_header->length=htons(sizeof(link_header_t)
                                             +sizeof(link_capabilities_t));
                   break;
                default:
                   fprintf(stderr,
                            "conn: asked to send capa reply on bad state!\n");
                   return -1;
             }
           break;
      
      case LINK_PK_TYPE_DH_HELLO:
           switch (conn->state){
                case CONN_STATE_CAPA_SENT:
		case CONN_STATE_DH_SENT:
                   if(NULL==conn->crypto_conn.as_link.dh){
                      conn->crypto_conn.as_link.dh=get_dh512();
                      if (NULL==conn->crypto_conn.as_link.dh){
                          fprintf(stderr,"cannot allocate dh space!\n");
                          exit(1);
                      }
                      if(1!=DH_generate_key(conn->crypto_conn.as_link.dh)){
                          fprintf(stderr,"Error generating dh key!\n");
                          exit(1);
                      }
                      //---------------
                      dh_hello=(link_dh_t *) (packet+sizeof(link_header_t));
                      dh_hello->key_size=htons(BN_bn2bin(conn->crypto_conn.as_link.dh->pub_key,
                                                         dh_hello->pubkey));
                      dh_hello->hash_size=0;
                      link_header->length=htons(sizeof(link_header_t)
                                             +sizeof(link_dh_t));        
                   } 
                   break;
                default:
                   fprintf(stderr,
                            "conn: asked to send dh hello on bad state!\n");
                   return -1;
             }
           break;

      case LINK_PK_TYPE_DH_HELLO_REPLY:
           switch (conn->state){
                case CONN_STATE_CAPA_RECV:
                case CONN_STATE_DH_REPSENT:
                   if(NULL==conn->crypto_conn.as_link.dh){
                     return -1;
                   }
                   dh_hello=(link_dh_t *) (packet+sizeof(link_header_t));
                   dh_hello->key_size=htons(BN_bn2bin(conn->crypto_conn.as_link.dh->pub_key, dh_hello->pubkey));
                   dh_hello->hash_size=0;
                   link_header->length=htons(sizeof(link_header_t)
                                             +sizeof(link_dh_t));

                   break;
                default:
                   fprintf(stderr,
                            "conn: asked to send dh hello reply on bad state!\n");
                   return -1;
             }
           break;
 
      //this is identical to dummy, maybe copy there?
      case LINK_PK_TYPE_ECHO_REQUEST:
           switch (conn->state){
                case CONN_STATE_ESTABLISHED:
                   capa_header=(link_capabilities_t *)
                                (packet+sizeof(link_header_t));
                   capa_header->version=LINK_VERSION;
                   capa_header->sym_alg=0;
                   capa_header->pub_type=0;
                   capa_header->magic=0;
                   link_header->length=htons(sizeof(link_header_t)
                                       +sizeof(link_capabilities_t));
                   break;
                default:
                   fprintf(stderr,
                           "conn: asked to send capahello on bad state!\n");
                   return -1;
             }
           break;



      default:
           fprintf(stderr,"unkown type to be sent!\n");
           return 0;
   }
   //and now send!!
   
   return link_send_packet(conn,packet,ntohs(link_header->length));

}
int send_link_data_packet(or_conn_t *conn,unsigned char *data,uint16_t datalen){
    unsigned char packet[2048];
    link_header_t *header;
    if(conn==NULL || data==NULL ||datalen>1500){
         fprintf(stderr,"cannot send link packet!\n");
         return -1;
    }
    //fill the packet with data   
    header=(link_header_t *)packet;
    memcpy(packet+sizeof(link_header_t),data,datalen);
    header->version= LINK_VERSION;
    header->type=LINK_PK_TYPE_DATA;
    header->length=ntohs(sizeof(link_header_t)+datalen);
    return link_send_packet(conn,packet,ntohs(header->length));

}


int handle_link_packet(unsigned char *data,size_t size,uint32_t remote_ip,uint16_t port){
   link_header_t *link_header;
   or_conn_t *conn;
//   fprintf(stderr,"*");   
   int rvalue;
   link_capabilities_t *capa_header;
   link_dh_t  *dh_header;
   BIGNUM *bn;

#ifdef DEBUG_LINK_CONN 
   fprintf(stderr,"*");
#endif
   if(size<sizeof(link_header_t)){
      fprintf(stderr,"bad in_size!\n");
      return -1;
   }
#ifdef DEBUG_LINK_CONN
   fprintf(stderr,"!");
#endif   
   link_header=(link_header_t *)data;
   conn=find_or_ins_conn_by_src_dst(&conn_db, remote_ip,port);
#ifdef DEBUG_LINK_CONN
    fprintf(stderr,"^");
#endif
   if(NULL==conn){
      fprintf(stderr,"cannot find/ins conn!");
      return -2;
   }
   if(link_header->version!=LINK_VERSION){
      fprintf(stderr,"bad link version\n");
      return -3;
   }
   //send to decrypt and verify!!
   rvalue=link_decrypt_verify_payload(conn,data,size);
   if(rvalue<=0){
      fprintf(stderr,"verified packet failed\n");
      return rvalue;
   }
#ifdef VERBOSE
   fprintf(stderr,"#");
#endif

   switch(link_header->type<<8 | conn->state){
       case LINK_PK_TYPE_DUMMY<<8|  CONN_STATE_DH_REPSENT:
       case LINK_PK_TYPE_DUMMY<<8|  CONN_STATE_ESTABLISHED:
            conn->state=CONN_STATE_ESTABLISHED;
            conn->crypto_conn.as_link.algo=CV_ALG_AES;
            conn->last_recv_sec=global_conf.current_time.tv_sec;
            fprintf(stderr,"}");
            break;

       /*beware of this one, goes with fallthrough!*/
       case LINK_PK_TYPE_CAPAHELLO <<8 | CONN_STATE_ESTABLISHED:
            if(size<sizeof(link_header_t)+sizeof(link_capabilities_t)){
              return -1;
            }
            if(conn->last_recv_sec+30>global_conf.current_time.tv_sec){
                //do nothing is very recent
                return 0;
            }
            if(conn->last_sent_sec+30<global_conf.current_time.tv_sec){
                //send an echo probe! I should send more than one tough!
                return send_link_state_packet(conn,LINK_PK_TYPE_ECHO_REQUEST);
            }
            //now it seems that the connection has been gone!
            fprintf(stderr,"Old connection is gone, starting a new one!\n");
            //start by cleaning up the old connection!
            //cleanup the db, reset values, change state
            cleanup_circuit_db(conn->circuit_db);    
            fprintf(stderr,"database is clean\n"); 
            //reset state
            conn->crypto_conn.as_link.algo=CV_ALG_NONE;
            conn->state=CONN_STATE_CAPA_RECV;
            rvalue=send_link_state_packet(conn,LINK_PK_TYPE_CAPAHELLOREPLY);
            if(rvalue>=0){
                //conn->state=CONN_STATE_CAPA_RECV;
            }
            fprintf(stderr,"after sent capa hello reply\n");
            return rvalue;

            break;

  
       /*Need to send capa reply!*/
       case LINK_PK_TYPE_CAPAHELLO<< 8 | CONN_STATE_NEW:
       case LINK_PK_TYPE_CAPAHELLO<< 8 | CONN_STATE_CAPA_RECV:
            if(size<sizeof(link_header_t)+sizeof(link_capabilities_t)){
              return -1;
            }
            fprintf(stderr,"/");
            conn->state=CONN_STATE_CAPA_RECV;
            rvalue=send_link_state_packet(conn,LINK_PK_TYPE_CAPAHELLOREPLY);
            if(rvalue>=0){
                //conn->state=CONN_STATE_CAPA_RECV;
            }
            
            return rvalue;
            break;
      
       /*need to send dhhello*/
       case LINK_PK_TYPE_CAPAHELLOREPLY<<8 | CONN_STATE_CAPA_SENT:
            //check for size, copy magic!
            if(size<sizeof(link_header_t)+sizeof(link_capabilities_t)){
              return -1;
            }
            capa_header=(link_capabilities_t *)(data+sizeof(link_header_t));
            fprintf(stderr,"\\");
            //next if conn magic==0
            conn->magic=capa_header->magic;
            conn->state=CONN_STATE_DH_SENT; 
            rvalue=send_link_state_packet(conn,LINK_PK_TYPE_DH_HELLO);
            if(rvalue>=0){
                //conn->state=CONN_STATE_DH_SENT;
            }
            break;

       /*need to send dh hello reply! and calculate secret!!*/
       case LINK_PK_TYPE_DH_HELLO <<8 | CONN_STATE_CAPA_RECV:
            if(size<sizeof(link_header_t)+sizeof(link_dh_t)){
              return -1;
            }
            fprintf(stderr,"@");
            //should check for magic
            dh_header=(link_dh_t *)(data+sizeof(link_header_t));
            //validate dh_header values!
            

            //now generate dh if needed and calculate secret!
            if(NULL==conn->crypto_conn.as_link.dh){
                conn->crypto_conn.as_link.dh=get_dh512();
                if (NULL==conn->crypto_conn.as_link.dh){
                   fprintf(stderr,"hl: cannot allocate dh space!\n");
                   exit(1);
                }
                if(1!=DH_generate_key(conn->crypto_conn.as_link.dh)){
                   fprintf(stderr,"hl: Error generating dh key!\n");
                   exit(1);
                }
            }
            bn=BN_new();
            assert(bn!=NULL);
            BN_bin2bn(dh_header->pubkey,ntohs(dh_header->key_size),bn);
            //now calculate secret
            //rvalue=DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
            rvalue=DH_compute_key(conn->crypto_conn.as_link.key,bn,conn->crypto_conn.as_link.dh);
            BN_free(bn);
            if(-1==rvalue){
                fprintf(stderr,"hl: Error computing dh key!\n");
                return -1;
            }
            fprintf(stderr,"key_len=%d\n",rvalue);
            fprint_hex(stderr,conn->crypto_conn.as_link.key,rvalue);
            fprintf(stderr,"\n");
            //now send packet!!
            conn->state=CONN_STATE_DH_REPSENT;
            //conn->crypto_conn.as_link.algo=CV_ALG_AES;
            rvalue=send_link_state_packet(conn,LINK_PK_TYPE_DH_HELLO_REPLY);
            break;

       case LINK_PK_TYPE_DH_HELLO_REPLY <<8 | CONN_STATE_DH_SENT:
            if(size<sizeof(link_header_t)+sizeof(link_dh_t)){
              return -1;
            }
            fprintf(stderr,"|");
            //should check for magic
            dh_header=(link_dh_t *)(data+sizeof(link_header_t));
            //validate dh_header values!
            //now calculate secret base on the reply value!
            bn=BN_new();
            BN_bin2bn(dh_header->pubkey,ntohs(dh_header->key_size),bn);
            //now calculate secret
            //rvalue=DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
            rvalue=DH_compute_key(conn->crypto_conn.as_link.key,bn,conn->crypto_conn.as_link.dh);
            BN_free(bn);
            if(-1==rvalue){
                fprintf(stderr,"hl: Error computing dh key!\n");
                return -1;
            }
            fprintf(stderr,"key_len=%d\n",rvalue);
            fprint_hex(stderr,conn->crypto_conn.as_link.key,rvalue);
            fprintf(stderr,"\n");
            conn->state=CONN_STATE_ESTABLISHED;
            conn->crypto_conn.as_link.algo=CV_ALG_AES;
            rvalue=send_link_state_packet(conn,LINK_PK_TYPE_DUMMY); 
            fprintf(stderr,"connected to: %u:%u for conn=%p",conn->remote_ip,conn->remote_port,conn);           
 
            break;




       case LINK_PK_TYPE_DATA<<8 | CONN_STATE_ESTABLISHED:
            //dont forget to try to deallocate DH space if allocated!!
#ifdef VERBOSE
            fprintf(stderr,"~");       
#endif     
            conn->last_recv_sec=global_conf.current_time.tv_sec; 
            return or_cell_handler(conn,data+sizeof(link_header_t),size-sizeof(link_header_t));
       case LINK_PK_TYPE_ECHO_REQUEST<< 8 | CONN_STATE_ESTABLISHED:
            rvalue=send_link_state_packet(conn,LINK_PK_TYPE_DUMMY);
            break;

       default:
            fprintf(stderr,"invalid conn recv?:%u:%u:",link_header->type,conn->state); 
            return -4;
   }
   

   return 0;
}
