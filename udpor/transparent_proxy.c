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


#include "tor-udp.h"
#include "cell_handler.h"
#include "tun_handler.h"
#include "socks.h"
#include "udp_transport.h"
#include <assert.h>
#include <string.h>

int transparent_proxy_build_forward_tcp_ip_header(or_stream_t *stream, unsigned char *buf){
    struct ip *ip_header;
    struct tcphdr *tcp;
    
    ip_header=(struct ip*) (buf); 
    tcp=(struct tcphdr *)(buf+20);
    
    //fill up necesary stuff!
    ip_header->ip_v=4;
    ip_header->ip_hl=5;
    ip_header->ip_p=IP_PROTO_TCP;   
    ip_header->ip_ttl=15;  //need to fix this!
    //no need to fill ip addresses?
    ip_header->ip_dst.s_addr=htonl(stream->local_ip);
    ip_header->ip_src.s_addr=htonl(stream->remote_ip);
    tcp->source=htons(stream->remote_port);
    tcp->dest  =htons(stream->local_port);
    tcp->doff  =5;
    
    

    return 0;
}


int tcp_packet_transparent_proxy_handle_forward(or_stream_t *stream, struct ip *ip_header,struct tcphdr *tcp){
    //this function assumes that the inpacket has been veirfied for length and that
    //the data lenghts have also been verified.
    unsigned char *in_packet;
    int rvalue;
    unsigned char outbuf[MAX_TUN_PACKET];
 
    //start via basic sanity checks!
    assert(NULL!=stream);
    assert(NULL!=ip_header);
    assert(NULL!=tcp);    

    in_packet=(unsigned char *)ip_header;

    //ok..
    assert(OR_STREAM_PROXY_STATE_NONE!=stream->proxy_state);
    switch(stream->proxy_state){
        case OR_STREAM_PROXY_STATE_NEW:
           if(tcp->syn!=1){
             return 0;
           }
           //we need to build a forward syn packet, copying the base stuff
           stream->out_packets=1; //to avoid rewriting..
           tcp->seq=htonl(ntohl(tcp->seq)-(sizeof(socks4_header_t)+2));//subtract what will be sent!
           tcp->window=htons(sizeof(socks4_header_t)); //make it a small window!
           break;
        case  OR_STREAM_PROXY_STATE_SYN_ACK_RECV:
           // we need to build a socks request!
           return 0;
           break;
        case  OR_STREAM_PROXY_STATE_READY:
           //if(tcp->)
           //do nothing for now!
           //return 0;
           break;
        default:
           return 0;
    }
  
    //now send the stream packet!
    //rvalue=build_tcp_stream_payload(stream,in_packet, outbuf);
    //return circuit_send_stream_payload(stream->parent_circuit,outbuf);
    return 0;
}



int tcp_packet_transparent_proxy_handle_reverse(or_stream_t *stream, unsigned const char *stream_payload){
   struct ip *ip_header;
   struct tcphdr *tcp;
   quasi_tcp_header_t *qtcp;
   quasi_tcp_header_t *new_qtcp;
   stream_header_t *stream_header;
   stream_header_t *new_stream_header;
   //stream_extra_header_t  *extrea_hdr;
   socks4_header_t *socks;
   int rvalue;
   const int socks_req_size=sizeof(socks4_header_t)+2;
   unsigned char buf[MAX_TUN_PACKET];
   unsigned char outbuf[MAX_TUN_PACKET];

   /*Do some base assertions*/
   assert(NULL!=stream);
   assert(NULL!=stream_payload);
   assert(IP_PROTO_TCP==stream->protocol);

   
   memset(buf,0x00,MAX_TUN_PACKET);
   memset(outbuf,0x00,MAX_TUN_PACKET);
  
   stream_header=(stream_header_t *)stream_payload;
   if(ntohs(stream_header->opt_length)>>13 !=0 ){
      return -1;
   }
   qtcp=( quasi_tcp_header_t *) (stream_payload+sizeof(stream_header_t));

   switch(stream->proxy_state){
       case OR_STREAM_PROXY_STATE_NEW:
          if(1==qtcp->syn && 1==qtcp->ack){
            fprintf(stderr,"transparent_proxy, got syn-ack!\n");
            //build and send socks4, finalize changin state
            //start with base tcp/ip stuff
            rvalue=transparent_proxy_build_forward_tcp_ip_header(stream, buf);
            fprintf(stderr,"^");
            ip_header=(struct ip *)buf;
            tcp=(struct tcphdr *) (buf+20); 
            tcp->seq    =qtcp->ack_seq;
            tcp->ack_seq=htonl(ntohl(qtcp->seq)+1);
            tcp->ack=1;
            tcp->window=htons(sizeof(socks4_header_t));
            //now fill                                              
            socks=(socks4_header_t *)(buf+40);
            socks->version=4;
            socks->command=0x01;
            socks->port=htons(stream->local_port);
            socks->dest=htonl(stream->local_ip);
            buf[40+sizeof(socks4_header_t)]='z'; 
            ip_header->ip_len=htons(40+socks_req_size);         

            //now store state for future
            stream->synack_opt_bytes=(qtcp->doff-5)*4;
            if(stream->synack_opt_bytes>OR_STREAM_ACK_COPY_SIZE){
                stream->synack_opt_bytes=OR_STREAM_ACK_COPY_SIZE;
            }
            fprintf(stderr,"syn_ack_bytes=%d\n",stream->synack_opt_bytes);
            memcpy(stream->synack_opt_data,qtcp+1, stream->synack_opt_bytes);

            stream->out_packets=1;
            fprintf(stderr,"aftel local allocs!!\n"); 
            rvalue=build_tcp_stream_payload(stream,buf, outbuf);
            fprintf(stderr,"$");
            //rvalue =circuit_send_stream_payload(stream->parent_circuit,outbuf);        
            fprintf(stderr,"/");
            stream->proxy_state=OR_STREAM_PROXY_STATE_SYN_ACK_RECV;
            return rvalue;
          }
          break;
       case OR_STREAM_PROXY_STATE_SYN_ACK_RECV:
          fprintf(stderr,"socks response? %d %d .",qtcp->syn,qtcp->ack);
          if(0==qtcp->syn && 1==qtcp->ack){
              
              //check if valid
              //ovewrite the data! to add the syn_ack info
              // and forward if it is!
              if(ntohs(stream_header->opt_length)!=
                      sizeof(socks4_header_t)+sizeof(quasi_tcp_header_t)+
                      sizeof(stream_header_t )+(qtcp->doff-5)*4){
                 fprintf(stderr,"bad header? size=%d\n",ntohs(stream_header->opt_length));
                 return 0;                
              }
              fprintf(stderr,"got socks response!"); 
           
              //copy data in local buf for manipulation!
              memcpy(buf,stream_payload,0x7FF & ntohs(stream_header->opt_length));  
 
              //extra size in bytes!                    
              rvalue=(stream->synack_opt_bytes>>2) +
                            (0x1 & ((stream->synack_opt_bytes)>>1 |(stream->synack_opt_bytes)));

              //now asign new headers
              new_stream_header=(stream_header_t *)buf;
              new_qtcp=( quasi_tcp_header_t *) (buf+sizeof(stream_header_t));

              //reset values
              new_stream_header->opt_length=htons(sizeof(quasi_tcp_header_t)+ sizeof(stream_header_t )+rvalue*4);
              new_stream_header->opt_length=htons(sizeof(quasi_tcp_header_t)+ sizeof(stream_header_t )+stream->synack_opt_bytes);
              
              //new_qtcp->doff=rvalue<<2+5;
              new_qtcp->doff=5+3;//+(stream->synack_opt_bytes/4);
              memcpy(new_qtcp+1,stream->synack_opt_data,3*4);
              new_qtcp->syn=1;
              new_qtcp->psh=0;          
              new_qtcp->seq=htonl(ntohl(qtcp->seq)+sizeof(socks4_header_t)-1); 
 
              rvalue=send_output_ip_packet(stream,buf);
              stream->proxy_state=OR_STREAM_PROXY_STATE_READY;
              return rvalue; 

          }
          return 0;
       case OR_STREAM_PROXY_STATE_READY:
          return send_output_ip_packet(stream,stream_payload);
          break;
       default:
          //wtf?
          return -1;
   }
  

   
   return 0;
}







