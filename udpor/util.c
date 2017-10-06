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


/*
The get ip address part, copied a lot from:
 http://www.hungry.com/~alves/local-ip-in-C.html
*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include "tor-udp.h"
#include "util.h"

#include "config.h"

//next for getip
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#include <string.h>
#include <openssl/rsa.h>


int fprint_hex(FILE *stream,const unsigned char *data, const uint32_t datalen){
  uint32_t i; 
  for(i=0;i<datalen;i++){
     fprintf(stream,"%02x",(unsigned char)data[i]);
  }
  return i;
}

int fprint_or_stream(FILE *stream,const or_stream_t *or_stream){
  return fprintf(stderr,"stream[%p]: loc %u:%u rem %u:%u\n",
                     or_stream, or_stream->local_ip, or_stream->local_port,
                     or_stream->remote_ip,or_stream->remote_port);
}

inline float tdiff(const struct timeval *t1, const struct timeval *t2){
   //calculates fabs(t1-t2)
   float temp;
   temp=t1->tv_usec-t2->tv_usec;
   return fabs(t1->tv_sec-t2->tv_sec+0.000001*temp);
}

int queue_drop_packet(const uint32_t packet_size,const struct timeval *current_time,bw_queue_state_t *queue ){
   int32_t new_queue_size;
   float prob; 
   float f_rand;
   //ensure that last time<=current time!

#ifdef DEBUG_UTIL
    fprintf(stderr,":");
#endif
   //calculate new size=max(0,last size-transmitted)
   new_queue_size=packet_size+queue->current_size-queue->kbps*125.0*(tdiff(current_time, &(queue->last_time))); //125 is x1000/8
   new_queue_size=(new_queue_size+abs(new_queue_size))>>1;

   //update queue last time
   //queue->last_time=*current_time;

   //now we determine what to do
   if(new_queue_size>queue->size){
      //fprintf(stderr,"new queue=%u , size=%d transmited=%f\n",new_queue_size,queue->size,queue->kbps*125*(tdiff(current_time, &(queue->last_time))));
      //fprintf(stderr,"time delta=%f\n", tdiff(current_time, &(queue->last_time)));
      return 0;
   }
   //fprintf(stderr,"time delta=%f\n", tdiff(current_time, &(queue->last_time)));

   if(new_queue_size>queue->threshold){
      //calculate drop probability and maybe drop
      prob=1.0*(new_queue_size-queue->threshold)/(1.0*queue->size-queue->threshold);
      f_rand=1.0*rand()/(1.0*RAND_MAX);
#ifdef DEBUG_UTIL
      fprintf(stderr,"{");
#endif
      if(prob>f_rand){
#ifdef DEBUG_UTIL
         fprintf(stderr,"}");
#endif
         return 0;
      }
      else{
         //fprintf(stderr,"prob=%f f_rand=%f\n",prob,f_rand);
      }
   }   
//accept_packet:
   queue->last_time=*current_time;
   queue->current_size=new_queue_size;   
#ifdef DEBUG_UTIL
   fprintf(stderr,"+");
#endif
   return packet_size;
}

uint32_t guess_ipv4_addr(){

#ifdef HAVE_IFADDRS_H
   struct ifaddrs *ifa = NULL, *ifp = NULL;
   char ip[200];
   socklen_t salen;
   uint32_t rvalue=0;
   struct sockaddr_in *ipv4_sock;

   if (getifaddrs (&ifp) < 0)  {
      perror ("getifaddrs");
      return 0;
   }
   if(NULL==ifp){
      return 0;
   }
   //fprintf(stderr,"++");
   for (ifa = ifp; ifa; ifa = ifa->ifa_next)  {
      if(NULL==ifa->ifa_addr){
        continue;
      }
      if (ifa->ifa_addr->sa_family == AF_INET){
         salen = sizeof (struct sockaddr_in);
         }
      else if (ifa->ifa_addr->sa_family == AF_INET6)
         salen = sizeof (struct sockaddr_in6);

      else{
         //fprintf(stderr,";");
         continue;
      }

      //fprintf(stderr,",");
      memset(ip,0x00,200);
/*
      if (getnameinfo (ifa->ifa_addr, salen,
                           ip, sizeof (ip), NULL, 0, NI_NUMERICHOST) < 0)      {
         perror ("getnameinfo");
         continue;
      }
*/
      if(ifa->ifa_addr->sa_family == AF_INET){
	 ipv4_sock=(struct sockaddr_in *)ifa->ifa_addr;
         if(ntohl(ipv4_sock->sin_addr.s_addr)>>24!=127){
	    //printf("%u\t ",ntohl(ipv4_sock->sin_addr.s_addr) );
            //printf ("%s\n", ip);
            rvalue=ntohl(ipv4_sock->sin_addr.s_addr);
            break;
         }

      }
      //fprintf (stderr,"%s\n", ip);
        
   
   }
   //fprintf(stderr,"--");

   freeifaddrs (ifp);
   return rvalue;
#else
   fprintf(stderr,"cannot determine ip_address!\n ");
   return 0;
#endif
}

int fprint_pub_conf(FILE *stream,const global_conf_t *conf,const bw_queue_state_t *queue){
   struct in_addr pub_addr;
   char *string_ip;

   pub_addr.s_addr=htonl(conf->advertised_ipv4);
   string_ip=inet_ntoa(pub_addr);   
   fprintf(stream,"\n-----START of PUB--------\n");
   fprintf(stream, "%s %d %d %d %d ",
                              string_ip,
                              conf->bind_port,
                              conf->is_client,
                              conf->is_exit,
                              queue->kbps);
   //need to fix, to write the bw of the system!
   //now the pki is written!
   BN_print_fp(stream,conf->rsa_key->e);
   fprintf(stream,",");
   BN_print_fp(stream,conf->rsa_key->n);   
   fprintf(stream,"\n");

   fprintf(stream,"-----END of PUB--------\n");   

  return 0;
}

int rsa_in_place_decrypt(RSA *rsa,unsigned char *in_out,uint16_t in_len,uint16_t max_out_len){
    unsigned char buff[2048];
    int rvalue;
    //sanity checks
    if(in_len>2048 || NULL==rsa || NULL==in_out || max_out_len>2048){
       return -1;
    }
    buff[0]=0; 
    //now decrpy into buff
    rvalue=RSA_private_decrypt(in_len,in_out,buff,rsa,RSA_PKCS1_OAEP_PADDING);
    if (rvalue<0){
       return rvalue;
    }    
    memcpy(in_out,buff,max_out_len); //this is just being lazy, sould be min
    return rvalue;
}

int rsa_in_place_encrypt(RSA *rsa,unsigned char *in_out,uint16_t in_len,uint16_t max_out_len){
    unsigned char buff[2048];
    int rvalue;
    //sanity checks
    if(in_len>2048 || NULL==rsa || NULL==in_out || max_out_len>2048){
       return -1;
    }
    buff[0]=0; 
    //now decrpy into buff
    rvalue=RSA_public_encrypt(in_len,in_out,buff,rsa,RSA_PKCS1_OAEP_PADDING);
    if (rvalue<0){
       return rvalue;
    }
    //fprintf(stderr,"encrypted %d bytes\n",rvalue);
    memcpy(in_out,buff,rvalue); //this is just being lazy, sould be min
    return rvalue;
}

