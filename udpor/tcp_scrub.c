/* (C) 2008 Camilo Viecco.  All rights reserved.
**
**  This file is part of Tdor, and is subject to the license terms in the
**  LICENSE file, found in the top level directory of this distribution. If you
**  did not receive the LICENSE file with this file, you may obtain it by contacting
**  the authors listed above. No part of Tdor, including this file,
**  may be copied, modified, propagated, or distributed except according to the
**  terms described in the LICENSE file.
*/


#include "tcp_scrub.h"


int sort_tcp_options(char *tcp_header){
   //not implemented yet
   return 0;
}



int in_place_tcp_forward_scrub(or_stream_t *in_stream, char *tcp_header){
   //assumes allocation of tcp header is at least 65 bytes long!
   //assumes also well formed option fields!
   int i,j;
   int opt_size;
   struct tcphdr *tcp_hdr;

   tcp_hdr=(struct tcphdr *)tcp_header;

   for(i=20;i<(tcp_hdr->doff*4);i++){
       switch(tcp_header[i]){
           case 0: //EOL  
                   tcp_header[i]=1; //make it a NOP 
                   break;
           case 1: //NOP
                   break;
           case 2: //MSS
           case 4: //SACK_PERMITTED
           case 5: //SACK
                   opt_size=tcp_header[i+1];                
                   i=i+opt_size-1;
                   break;
           case 3: //WSOPT
                   if(1==tcp_hdr->syn && 3==tcp_header[i+1]){
                      opt_size=tcp_header[i+1];
                      if(tcp_header[i+2]>3){//only do stuff if win is large!
                          in_stream->win_comp=tcp_header[i+2]-3;
                          tcp_header[i+2]=3;
                      }
                      i=i+opt_size-1;
                      break;
                   }
                   in_stream->win_comp=0; //just in case!
                   //else, fallthrough and clean opt!

           default:
                   //set to NOP
                   opt_size=tcp_header[i+1];
                   for(j=i;j<(tcp_hdr->doff*4) && j<i+opt_size;j++){
                      tcp_header[j]=1;
                   }
                   i=i+opt_size-1;
                   break;
       }

   }
   //now modify the seq number!!
   tcp_hdr->seq=htonl(ntohl(tcp_hdr->seq)+in_stream->seq_add);
   
   //now modify the window size, by bounding and shifting by the
   //compensation factor
   if(0== (ntohs(tcp_hdr->window) >> (16-in_stream->win_comp)) )
     tcp_hdr->window=htons(ntohs(tcp_hdr->window)<<in_stream->win_comp);
   else
     tcp_hdr->window=0xFFFF;
   //now bound the syn window to 32K 
   if(1==tcp_hdr->syn && ntohs(tcp_hdr->window)>0x8000){
        tcp_hdr->window=htons(0x8000);
     }
  

   sort_tcp_options(tcp_header);
   return 0;
}

int in_place_tcp_reverse_scrub(const or_stream_t *out_stream, char *tcp_header){
   //this function does NOT aler the packet size!
   //this  blanks out all options but: 
   //      NOP,EOL,MSS, SACK permitted, SACK_OPTION,WINDOW SCALE
   // 
   //this function also reverses the seq deltas in ACK data
   // this function will also do some magic on the Window SCAle
   
   //assumes the allocation for tcp_header is at least 65 bytes long!

   // this function also assumes that the options are well formed!


   int i,j;
   int opt_size;
   struct tcphdr *tcp_hdr;
   uint32_t *sack_edge;
   tcp_hdr=(struct tcphdr *)tcp_header;

   for(i=20;i<(tcp_hdr->doff*4);i++){ 
       switch(tcp_header[i]){
           case 0: //EOL
           case 1: //NOP
                   break;
           case 2: //MSS
           case 3: //WSOPT
           case 4: //SACK_PERMITTED
                   opt_size=tcp_header[i+1];                 
                   i=i+opt_size-1;
                   break;
           case 5: //SACK
                   opt_size=tcp_header[i+1];
                   for(j=i+2;j<(tcp_hdr->doff*4) && j<i+opt_size;j+=4){
                       sack_edge=(uint32_t *)(tcp_header+j);
                       *sack_edge=htonl(ntohl(*sack_edge)-out_stream->seq_add);
                   }
                   i=i+opt_size-1;
                   break;

           default:
                   //set to NOP
                   opt_size=tcp_header[i+1];
                   for(j=i;j<(tcp_hdr->doff*4) && j<i+opt_size;j++){
                      tcp_header[j]=1;
                   }
                   i=i+opt_size-1;  
       }     

   }
   //now modify the ack number!!
   tcp_hdr->ack_seq=htonl(ntohl(tcp_hdr->ack_seq)-out_stream->seq_add);
   

   //sort_tcp_options();
   return 0;
}



