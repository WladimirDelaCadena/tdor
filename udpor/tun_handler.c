\
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
This file in in charge of handling packets that arrive via the tunnel interface
or that need to be send via the tunnel interface.

*/


#include "tun_handler.h"
#include <stdio.h>
#include "tor-udp.h"
#include <dnet.h>
#include <unistd.h>
#include <string.h>
#include "dh_params.h"
#include <stdlib.h>
#include "link_conn.h"
#include "internal_db.h"
#include "cell_handler.h"
#include "udp_transport.h"
#include "tcp_scrub.h"
#include "util.h"
#include "transparent_proxy.h"


//enums
#include <netinet/in.h>

//#define DEBUG_TUN_HANDLER

extern stream_db_t stream_db;
extern conn_db_t conn_db;
extern const global_conf_t global_conf;
int index_c=0;
//
//Next function is a wrapper for tun_send as it is broken on Linux and I have not made
// the manainter fix it so I am wrapping this thing!
//
ssize_t Tun_Send(tun_t *t, const void *buf, size_t size){
#ifdef LINUX
   struct iovec iov[2];
   uint32_t type = htonl(ETH_TYPE_IP);

   iov[0].iov_base = &type;
   iov[0].iov_len = sizeof(uint32_t);
   iov[1].iov_base = (void *)buf;
   iov[1].iov_len = size;

   return (writev(tun_fileno(t), iov, 2));
#else
   return tun_send(t,buf,size);
#endif

}



int tun_send_icmp_fail(tun_t *tun,int type,int code,unsigned char *orig_packet,int orig_size){
   char buf[MAX_TUN_PACKET];
   struct ip *ip_header,*new_header;
   struct icmphdr *icmp_header;
   int copylen;
   
   ip_header=(struct ip *)orig_packet;
   copylen=ip_header->ip_hl*4+64;
   if(copylen>orig_size){
      copylen=orig_size;
   }
   memcpy(buf+sizeof(struct ip)+sizeof(struct icmphdr),orig_packet,copylen);   
   new_header=(struct ip *)buf;
   icmp_header=(struct icmphdr *)(buf+sizeof(struct ip)); 
   //--setup ip values
   new_header->ip_v=4;
   new_header->ip_hl=5;
   new_header->ip_p=IP_PROTO_ICMP;
   new_header->ip_src=ip_header->ip_dst;
   new_header->ip_dst=ip_header->ip_src;
   new_header->ip_ttl=32;
   new_header->ip_len=htons(copylen+sizeof(struct ip)+sizeof(struct icmphdr));
   //--setup icmp values
   icmp_header->type=type;
   icmp_header->code=code;
   icmp_header->checksum=0;
   //---now fix checksums
   ip_checksum(new_header,copylen+sizeof(struct ip)+sizeof(struct icmphdr));

   return Tun_Send(tun,buf,copylen+sizeof(struct ip)+sizeof(struct icmphdr));
 
   //return 0;
}


int build_tcp_stream_payload(or_stream_t *stream, unsigned char *inpacket, unsigned char *out){
   //assumes out buffer is assigned!
   // and that the input packet has been validated!
   //fprintf(stderr,"Building tcp to tunnel ....");
   stream_header_t *out_header;
   quasi_tcp_header_t *or_tcp;
   stream_extra_header_t *stream_extra;
   struct ip *ip;
   struct tcphdr *tcp;
   uint16_t copy_size;
   uint16_t q_tcp_offset=0;
   uint16_t stream_opt_val=0;

   //better to check also for non udp?
   if(0==stream->out_packets){

      q_tcp_offset=sizeof(stream_extra_header_t);
      stream_extra=(stream_extra_header_t *)(out+sizeof(stream_header_t));
      stream_extra->proto=stream->protocol;
      stream_extra->dst_port=ntohs(stream->local_port);
      stream_extra->reserve=0x00;
      stream_opt_val=0x4;
      fprintf(stderr,"built tcp stream, port=%d\n",stream->local_port);

   }

   out_header=(stream_header_t *)out;
   or_tcp=(quasi_tcp_header_t*)(out+sizeof(stream_header_t)+q_tcp_offset);
   ip=(struct ip*)inpacket;
  
   tcp=(struct tcphdr *)(inpacket+ip->ip_hl*4);
 
   //now we copy the tcp header without the options
   memcpy(or_tcp,&(tcp->seq),sizeof(quasi_tcp_header_t));
   //now we manually copy the urgent pointer
   or_tcp->urg_ptr = tcp->urg_ptr;  

   //now we copy the rest of the package, including TCP options
   copy_size=ntohs(ip->ip_len)-ip->ip_hl*4-sizeof(struct tcphdr); 
   memcpy(out+sizeof(quasi_tcp_header_t)+sizeof(stream_header_t )+q_tcp_offset,
          inpacket+ip->ip_hl*4+sizeof(struct tcphdr),
          copy_size);

   //we now fill the stream header
   out_header->stream_id=htons(stream->stream_id & 0xFFFF);
   out_header->opt_length=htons((copy_size+sizeof(quasi_tcp_header_t)+sizeof(stream_header_t )+q_tcp_offset) | stream_opt_val<<13);
#ifdef DEBUG_TUN_HANDLER
   fprintf(stderr,"stream to be sent! id=%x\n",stream->stream_id & 0xFFFF);
   fprint_hex(stderr,out,20);
   fprintf(stderr,"\n");

   fprintf(stderr,"orig tcp from seq:");
   fprint_hex(stderr,(char *)&(tcp->seq),16);
   fprintf(stderr,"\n");  
#endif
#ifdef VERBOSE
   fprintf(stderr,"out_stream len=%d\n",ntohs(out_header->opt_length)&0x1FFF);
#endif
   return 0;
}

int send_output_ip_packet(or_stream_t *stream,unsigned const char *in_stream ){
   struct ip *ip;
   struct tcphdr *tcp;
   quasi_tcp_header_t *or_tcp;
   stream_header_t *stream_header;
   unsigned char buffer[MAX_TUN_PACKET];
   int copy_size; 
   uint16_t packet_size=0; 
   uint8_t stream_data_offset=0;
   tun_t *tun=global_conf.tun; 

   stream_header=(stream_header_t *)in_stream;
   ip=(struct ip *)buffer;
   tcp=(struct tcphdr *)(buffer+sizeof(struct ip));// no ip options!

#ifdef DEBUG_TUN_HANDLER
   fprintf(stderr,"send output stream:\n");
   fprint_hex(stderr,in_stream,16);
   fprintf(stderr,"\n");
#endif
 
   //common for all!
   memset(buffer,0x00,sizeof(struct ip));
   ip->ip_v=4;
   ip->ip_hl=5;
   ip->ip_ttl=16;

   stream_data_offset=sizeof(stream_extra_header_t)*ntohs(stream_header->opt_length)>>15;

#ifdef DEBUG_TUN_HANDLER
    fprintf(stderr,"stream_data_offset=%d\n",stream_data_offset);
#endif

   switch(ntohs(stream_header->opt_length)>>13){
       case 0x4:
       case 0x0:
          //fprintf(stderr,"handling output tcp with no options!");
          or_tcp=(quasi_tcp_header_t *)(in_stream+sizeof(stream_header_t)+stream_data_offset);
          //rebuild the ip header!
          ip->ip_p=IP_PROTO_TCP;
          ip->ip_id=rand();
          ip->ip_src.s_addr=htonl(stream->local_ip);
          ip->ip_dst.s_addr=htonl(stream->remote_ip); 
          ip->ip_len=htons((ntohs(stream_header->opt_length) & 0x1FFF) +
                        sizeof(struct ip) +
                        sizeof(struct tcphdr) -
                        sizeof(quasi_tcp_header_t) -
                        sizeof(stream_header_t ) - stream_data_offset); 

          //rebuild the tcp header
          tcp->dest=htons(stream->remote_port);
          tcp->source=htons(stream->local_port);
          //copy the rest!
          memcpy(&(tcp->seq),or_tcp,sizeof(quasi_tcp_header_t));
          tcp->urg_ptr = or_tcp->urg_ptr;
          
          //now we build the payload and the tcp options!
          copy_size=(ntohs(stream_header->opt_length) & 0x1FFF)-sizeof(quasi_tcp_header_t)-sizeof(stream_header_t )-stream_data_offset;
          //fprintf(stderr,"copy_size=%d\n",copy_size);
          memcpy(buffer+sizeof(struct ip)+sizeof(struct tcphdr),
                in_stream+sizeof(quasi_tcp_header_t)+sizeof(stream_header_t )+
                    stream_data_offset,
                copy_size); 

     
          //now we calculate the packet sise
          packet_size=copy_size+sizeof(struct ip)+sizeof(struct tcphdr);

          //we now scrub the data
          in_place_tcp_reverse_scrub(stream, (char *)tcp);

          //now fill checksums!
          //ip_checksum(buffer,packet_size);
          //fprintf(stderr,"after checksum!\n");
          //and finalize by sending!
          //return Tun_Send(tun,buffer,packet_size);
          break;
       default:
          fprintf(stderr,"cannot handle case!\n");
          return 0;
          break;
   }

   //increment stream statistics...
   stream->out_packets++;

   //now fill checksums!
   ip_checksum(buffer,packet_size);
   //fprintf(stderr,"after checksum!\n");
   //and finalize by sending!
   return Tun_Send(tun,buffer,packet_size);

}


int tun_send_icmp_echo_reply(tun_t *tun,unsigned char *orig_packet,int orig_size){
   char buf[MAX_TUN_PACKET];
   struct ip *ip_header,*new_header;
   struct icmphdr *icmp_header,*orig_header;
   int copylen;

   ip_header=(struct ip *)orig_packet;
   copylen=orig_size-ip_header->ip_hl*4-sizeof(struct icmp_hdr);
   orig_header=(struct icmphdr *)(orig_packet+ip_header->ip_hl*4);
   /*
   memcpy(buf+sizeof(struct ip)+sizeof(struct icmphdr),
          orig_packet+ip_header->ip_hl*4+sizeof(struct icmp_hdr),
          copylen);
   */
   memcpy(buf+sizeof(struct ip)+sizeof(struct icmphdr),
          orig_packet+ip_header->ip_hl*4+sizeof(struct icmphdr),
          copylen);
   new_header=(struct ip *)buf;
   icmp_header=(struct icmphdr *)(buf+sizeof(struct ip));
   //--setup ip values
   new_header->ip_v=4;
   new_header->ip_hl=5;
   new_header->ip_p=IP_PROTO_ICMP;
   new_header->ip_src=ip_header->ip_dst;
   new_header->ip_dst=ip_header->ip_src;
   new_header->ip_ttl=32;
   new_header->ip_off=0;
   new_header->ip_len=htons(copylen+sizeof(struct ip)+sizeof(struct icmphdr));
   //--setup icmp values
   icmp_header->type=0;
   icmp_header->code=0;
   icmp_header->checksum=0;
   icmp_header->un.echo.id=orig_header->un.echo.id;
   icmp_header->un.echo.sequence=orig_header->un.echo.sequence;
   //---now fix checksums
   ip_checksum(new_header,copylen+sizeof(struct ip)+sizeof(struct icmphdr));

   return Tun_Send(tun,buf,copylen+sizeof(struct ip)+sizeof(struct icmphdr));


}


int handle_local_icmp(){
   return 0;
}

int handle_tunnel_packet(tun_t *tun){
   // returns how many bytes are processed!

   //read fd,
   //if src_ip/port is not known
   //  allocate new, calculate, send reply mesage
   //else
   //  pass with ID to cell handler
   
   int data_len;
   struct ip *ip_header;
   struct icmphdr *icmp_header;
   struct tcphdr *tcp;
   or_stream_t *stream;
   or_stream_t *stream_sec;
   or_circuit_t *circuit;
   or_circuit_t *circuit_sec;   
   static uint32_t stream_id=0;
   static uint32_t stream_id_sec=0;
   int rvalue;
   unsigned char buf[MAX_TUN_PACKET];
   unsigned char outbuf[MAX_TUN_PACKET];
   struct in_addr net_addr;
   or_stream_t new_stream;
   or_stream_t new_stream2;

   data_len=tun_recv(tun,buf,MAX_TUN_PACKET);
   
   if(data_len<sizeof(struct ip)){
      return 0;
   }
   ip_header=(struct ip*)buf;
   //check for basic sanity
   if( 4!=ip_header->ip_v ||
       5<ip_header->ip_hl || (data_len<ip_header->ip_hl*4)){
       fprintf(stderr,"invalid_packet!\n");
       return 0;
   }
   // now check recived len vs actual len
   if(data_len<ntohs(ip_header->ip_len)){
       fprintf(stderr,"packet too short!\n");
       return 0;
   }
   //should we check for fragmentation too?

   //if client or exit try to find related

   //now se process according to the protcol
#ifdef VERBOSE
   fprintf(stderr,"-");
#endif
   switch(ip_header->ip_p){
       case IP_PROTO_TCP:
              if(data_len<sizeof(struct tcphdr)+ip_header->ip_hl*4){
                 fprintf(stderr,"packet to small for tcp!\n");
                 return -1;
              }
#ifdef VERBOSE
              fprintf(stderr,".\n");
#endif
              tcp=(struct tcphdr *)(buf+ip_header->ip_hl*4);
              //search stream primary
              stream = find_stream_by_ip_port(&stream_db,
                              ntohl(ip_header->ip_dst.s_addr),
                              ntohl(ip_header->ip_src.s_addr),
                              ntohs(tcp->dest),
                              ntohs(tcp->source), 
                              IP_PROTO_TCP);
	    

              if(NULL==stream){
                 // find local stream circuits , primary and secondary!
		 
                 circuit = find_local_circuit(&conn_db,0);
   		 circuit_sec = find_local_circuit(&conn_db,1);
                 fprintf(stderr,"--------------------\n"); 
		if(circuit!=NULL){
                    //clear up
                    memset(&new_stream,0x00,sizeof(or_stream_t));
                    //fill new stream, then collect it from the db!
                    new_stream.local_ip=ntohl(ip_header->ip_dst.s_addr);
                    new_stream.remote_ip=ntohl(ip_header->ip_src.s_addr);
                    new_stream.local_port= ntohs(tcp->dest);
                    new_stream.remote_port=ntohs(tcp->source);
                    new_stream.protocol=IP_PROTO_TCP;
                    new_stream.stream_id=stream_id; 
                    new_stream.parent_circuit=circuit;
                    new_stream.secondary_circuit=circuit_sec;
                    //index_c++;
                    new_stream.seq_add=rand_r((unsigned int *)&circuit->isv_seed)-
                                       ntohl(tcp->seq);
		    //fprintf(stderr, "Current remote_ip: %i\n" , new_stream.remote_ip); 
                    //Now determine if this stream requires transparent
                    // natting!
                    if(0==inet_aton(global_conf.net_addr,&net_addr)){
                         fprintf(stderr,"bad net address\n");
                         exit(1);
                    }            
                    net_addr.s_addr=htonl(ntohl(net_addr.s_addr)+1);
                    if(ip_header->ip_dst.s_addr!=net_addr.s_addr){
                       fprintf(stderr,"wow, tranparent proxy\n");
                       new_stream.proxy_state=OR_STREAM_PROXY_STATE_NEW;   
                    } 

                    stream_id++;
                    stream=insert_stream_into_db(&stream_db,&new_stream);
                    fprintf(stderr, "new stream!\n");
                    fprint_or_stream(stderr,stream);
                 }
                 else{
                     fprintf(stderr,"no local circuit found!\n");
                     fprintf(stderr,"%u:%d %u:%d %d",ntohl(ip_header->ip_dst.s_addr),ntohs(tcp->dest),ntohl(ip_header->ip_src.s_addr),ntohs(tcp->source),IP_PROTO_TCP );
                     return tun_send_icmp_fail(tun,3,2,buf,data_len);
                 }
              }
              //we update the stream time   
              stream->last_time=global_conf.current_time.tv_sec;

              //we now scrub the data!
              in_place_tcp_forward_scrub(stream, (char *)tcp);
              //if requires proxy,call proxy
              if(OR_STREAM_PROXY_STATE_NONE!=stream->proxy_state){
                 return  tcp_packet_transparent_proxy_handle_forward(stream,ip_header, tcp);    
              }
             
              //now we encapsulate and send!          
              rvalue=build_tcp_stream_payload(stream,buf, outbuf);
              
              //actually should send with the exeption of proxy ready and syn!
              //ignore this for now
              return circuit_send_stream_payload(stream->parent_circuit, stream->secondary_circuit,outbuf);  
             
              //return tun_send_icmp_fail(tun,3,2,buf,data_len);             
              break;
       case IP_PROTO_UDP:
              return 0;
              break;
       case IP_PROTO_ICMP:
              if(ip_header->ip_len<sizeof(struct icmphdr)+ip_header->ip_hl*4){
                return 0;
              }
              icmp_header=(struct icmphdr *)(buf+ip_header->ip_hl*4);
              switch(icmp_header->type){
                  case ICMP_ECHO:
                     return tun_send_icmp_echo_reply(tun,buf,data_len);                     
                  default:
                     return 0;
              }
              break;
       default:
              fprintf(stderr,"unrecognized protocol!\n");
              return 0;
              break;
   }
}
