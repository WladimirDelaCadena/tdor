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
#include <string.h>
#include "udp_transport.h"
#include "tor-udp.h"
//#include "circuit_crypto.h"
#include "dh_params.h"
#include <openssl/sha.h>
#include "internal_db.h"
#include "link_conn.h"
#include "util.h"
#include "cell_handler.h"
#include <assert.h>
#include "tun_handler.h"
#include "transparent_proxy.h"


//testing debugs
//#define DEBUG_CELL_HANDLER

//#define VERBOSE

///-------
extern conn_db_t conn_db;
extern const global_conf_t global_conf;
extern stream_db_t stream_db;

//--------
int print_circuit_conn_details(or_circuit_t *circuit){
  assert(circuit!=NULL);
  assert(circuit->or_conn!=NULL);
  fprintf(stderr,"circuit=%p circuit_id=%x state[0]=%d ",circuit,circuit->circuit_id,circuit->state[0]);
  fprintf(stderr,"ip_addr=%u port=%d\n",circuit->or_conn->remote_ip,circuit->or_conn->remote_port);
  return 0;
}


//-----------------------

int or_circuit_encypt_cell(unsigned char *cell,or_circuit_t *circuit,int forward,int depth){
   int i;
   cell_header_t *header;
   unsigned char buffer[1024];
   unsigned char buffer2[1024];
   unsigned char *indata;
   uint16_t datalen;
   unsigned char checksum[20];
   AES_KEY aes_key;
   BF_KEY bf_key;
   unsigned char iv[256];


   header=(cell_header_t *)cell;
   //check for version
   if(OR_CELL_VERSION!=header->version || header->size>8){
      fprintf(stderr,"encrypt cell: bad version or header:"
                     " version=%d size=%d\n",header->version,header->size);
      return -1;
   }
   //header->init_vector.as_uint64=rand(); //this is sooo wrong!

   //the 8 value comes from the size of the checksum+type
   indata=(unsigned char *)(cell+sizeof(cell_header_t)-8);
   datalen=header->size*128-sizeof(cell_header_t)+8;
  
   //now align the datalen to the 16 bytes!
   datalen=(datalen+15>>4)<<4;

   if(0==forward){
      //put iv AND put sha
      header->init_vector.as_uint64=rand(); //this is sooo wrong!
      //calculate the sha and write it!!!
      //SHA1(indata+7,datalen-7,header->checksum.as_uchar);
      SHA1(indata+7,datalen-7,checksum);
      memcpy(header->checksum.as_uchar,checksum,7);

#ifdef DEBUG_CELL_HANDLER
      fprintf(stderr,"Encypting datalen=%d\n",datalen-7);
      fprintf(stderr,"checksum:\n");
      fprint_hex(stderr,header->checksum.as_uchar, 7);
      fprintf(stderr,"\n");
/*   fprint_hex(stderr,cell, 16);
      fprintf(stderr,"\nindata:");
      fprint_hex(stderr,indata, 16);
      fprintf(stderr,"\nindata+7:");
      fprint_hex(stderr,indata+7, 16);
*/
#endif
   //now something nasty!
   }

   circuit->sym_crypto_info[0].alg=OR_CRYPTO_ALG_AES;
  // circuit->sym_crypto_info[1].alg=OR_CRYPTO_ALG_AES; 
  // circuit->sym_crypto_info[2].alg=OR_CRYPTO_ALG_AES;


   //initialize
   buffer[0]=0;

   //for (i=circuit->num_cryptos-1;i>=0;i--){
   for(i=depth-1;i>=0;i--){
       switch((circuit->sym_crypto_info)[i].alg){
            case OR_CRYPTO_ALG_NONE:
               break;
            case OR_CRYPTO_ALG_AES:
                 AES_set_encrypt_key( circuit->sym_crypto_info[i].key.key, 128,&aes_key);
                 memset(iv,0x00,256);
                 memcpy(iv,header->init_vector.as_uchar,8); 
                 AES_cbc_encrypt(indata,
                                 buffer,
                                 datalen,
                                 //&(circuit->sym_crypto_info[i].key.aes.encrypt),
                                 &aes_key,
                                 iv,
                                 AES_ENCRYPT);




#ifdef DEBUG_CELL_HANDLER
                 fprintf(stderr,"Ecncryption:\n");
                 fprintf(stderr,"iv=\n",datalen);
                 fprint_hex(stderr,header->init_vector.as_uchar, 8);
                 fprintf(stderr,"\n");
 
                 fprintf(stderr,"datalen=%d\n pre=\n",datalen);
                 fprint_hex(stderr,indata, 32);
                 fprintf(stderr,"\n");
                 fprintf(stderr," post=\n");
                 fprint_hex(stderr,buffer, 32);
                 fprintf(stderr,"\n");
                
                 fprintf(stderr," header=\n");
                 fprint_hex(stderr,(char *)header, 24);
                 fprintf(stderr,"\n");

#endif
 
                 memcpy(indata,buffer,datalen);


                 break;
            case OR_CRYPTO_ALG_BLOWFISH:
                 memset(&bf_key,0x00,sizeof(BF_KEY));
                 memset(iv,0x00,256);
                 memcpy(iv,header->init_vector.as_uchar,8);

                 BF_set_key(&bf_key,16,circuit->sym_crypto_info[i].key.key);
                 BF_cbc_encrypt(indata,
                                buffer,
                                datalen,
                                //&(circuit->sym_crypto_info[depth].key.bf),
                                &bf_key,
                                //header->init_vector.as_uchar,
                                iv,
                                BF_ENCRYPT);
#ifdef DEBUG_CELL_HANDLER
                fprintf(stderr,"key=\n",datalen);
                fprint_hex(stderr,circuit->sym_crypto_info[i].key.key, 64);
                fprintf(stderr,"\n");

                fprintf(stderr,"iv=\n",datalen);
                fprint_hex(stderr,iv,8);//header->init_vector.as_uchar, 8);
                fprintf(stderr,"\n");


                fprintf(stderr,"datalen=%d\n pre=\n",datalen);
                fprint_hex(stderr,indata, 24);
                fprintf(stderr,"\n");
                fprintf(stderr," post=\n",datalen);
                fprint_hex(stderr,buffer, 24);
                fprintf(stderr,"\n");


                 memset(&bf_key,0x00,sizeof(BF_KEY));
                 memset(iv,0x00,256);
                 memcpy(iv,header->init_vector.as_uchar,8);

                 BF_set_key(&bf_key,16,circuit->sym_crypto_info[i].key.key);
                 BF_cbc_encrypt(buffer,
                                buffer2,
                                datalen,
                                //&(circuit->sym_crypto_info[depth].key.bf),
                                &bf_key,
                                //header->init_vector.as_uchar,
                                iv,
                                BF_DECRYPT);
                fprintf(stderr,"datalen=%d\n pre=\n",datalen);
                fprint_hex(stderr,buffer, 24);
                fprintf(stderr,"\n");
                fprintf(stderr," post=\n",datalen);
                fprint_hex(stderr,buffer2, 24);
                fprintf(stderr,"\n");
#endif



                 memcpy(indata,buffer,datalen);
                 break;
            default:
                 return -1;

       }
   } 
   return datalen;
}

//--------------------------------------------

int or_circuit_send_cell(or_circuit_t *circuit,unsigned char *cell,int depth){
  //assumes in cell is in plaintext! and and is well formed!
  int rvalue;  
  cell_header_t *header;


  //encrypt cell... asummes it is well formed!!
  rvalue=or_circuit_encypt_cell(cell,circuit,0,circuit->num_cryptos);
  if(rvalue<0){
     fprintf(stderr,"cennot encrypt cell!\n");
     return -1;
  }  



  header=(cell_header_t *)cell;
  //cell->
#ifdef VERBOSE
  fprintf(stderr,"or: calling send_link_data packet! outsize=%d\n",header->size<<7);
#endif
#ifdef DEBUG_CELL_HANDLER
  fprintf(stderr,"sending cell \n");
  fprint_hex(stderr,cell, 24);
  fprintf(stderr,"\n");
#endif

  return send_link_data_packet(circuit->or_conn,cell,header->size<<7);
};

//--------------------------------------------------
//These two ^ and v should be integrated into one function!
//--------------------------------------------------
int or_circuit_send_forward_cell(or_circuit_t *circuit,unsigned char *cell){
  //assumes in cell is in plaintext! and and is well formed!
  int rvalue;
  cell_header_t *header;

  header=(cell_header_t *)cell;
  header->circuit_id_high=circuit->circuit_id>>16;
  header->circuit_id_low =htons(circuit->circuit_id &0xFFFF);

  //encrypt cell... asummes it is well formed!!
  rvalue=or_circuit_encypt_cell(cell,circuit,1,circuit->num_cryptos);
  if(rvalue<0){
     fprintf(stderr,"cennot encrypt cell!\n");
     return -1;
  }
  header=(cell_header_t *)cell;
  //cell->
#ifdef VERBOSE
  fprintf(stderr,"fw: calling send_link_data packet! outsize=%d\n",header->size<<7);
#endif
  return send_link_data_packet(circuit->or_conn,cell,header->size<<7);
};

/////////////----------------------------------------
//
/////////////----------------------------------------



int or_circuit_send_relay_command_cell(or_circuit_t *circuit,unsigned char *cell){
  //assumes in cell is in plaintext! and and is well formed!
  int rvalue;
  cell_header_t *header;
  //no crypto, replace circuit id only!

  header=(cell_header_t *)cell;
  header->circuit_id_high=circuit->circuit_id>>16;
  header->circuit_id_low =htons(circuit->circuit_id &0xFFFF);
#ifdef DEBUG_CELL_HANDLER
  fprintf(stderr,"about to send relay command cell, size=%d\n",header->size<<7);
  fprint_hex(stderr,cell, 24);
  fprintf(stderr,"\n");

#endif
  return send_link_data_packet(circuit->or_conn,cell,header->size<<7);
};

//--------------------------------------------------
int circuit_send_stream_payload(or_circuit_t *circuit,unsigned char *stream_payload){
   //fprintf(stderr,"sending data!!\n");
   unsigned char buffer[1024];
   cell_header_t *header;
   stream_header_t *stream;
   int cell_len;  

   header=(cell_header_t *)buffer;
   header->circuit_id_high=circuit->circuit_id>>16;
   header->circuit_id_low =htons(circuit->circuit_id &0xFFFF);
   stream=(stream_header_t *)stream_payload;
   memcpy(buffer+sizeof(cell_header_t),stream_payload,ntohs(stream->opt_length) & 0x1FFF);
   header->version=OR_CELL_VERSION;
   cell_len=(ntohs(stream->opt_length) & 0x1FFF) +sizeof(cell_header_t);
   header->size=(cell_len+127)>>7;
   header->command=COMMAND_STREAM_DATA;
   header->command_status= STATUS_REQUEST;

#ifdef VERBOSE   
   fprintf(stderr,"circuit to be sent! \n");
//   fprint_hex(stderr,buffer,36);
//   fprintf(stderr,"\n");

   fprintf(stderr,"cell info: len=%d size=%d\n",cell_len,header->size);
#endif
    
   return or_circuit_send_cell(circuit,buffer,circuit->num_cryptos);   
   //return 0;
}

//-----------------------------------------------------

int or_circuit_decrypt_validate_cell(or_circuit_t *circuit,unsigned char *cell,int depth){
  //this function returns:
  // -1 error
  // 0 packet probably needs forwarding
  // n depth of analysis -1!!
   //int i;
   cell_header_t *header;
   unsigned char buffer[2048];
   //unsigned char buffer2[2048];
   unsigned char checksum[128];
   unsigned char iv[256];
   unsigned char *indata;
   int16_t datalen;
   int enc_offset;
   int rvalue;
   AES_KEY aes_key;
   BF_KEY  bf_key;
   

   //base case.. this funciton is recursive!
   if (depth>circuit->max_level){
      return 0; // maybe -1 is a better option?
   }


   header=(cell_header_t *)cell;
   //check for version
   if(OR_CELL_VERSION!=header->version || header->size>8){
//#ifdef DEBUG_CELL_HANDLER
      fprintf(stderr,"decrypt-validate cell: bad version or size\n"); 
      fprintf(stderr,"version=%d, size=%d\n",header->version,header->size);
      fprint_hex(stderr,cell, 16);
      fprintf(stderr,"\n");

//#endif

      return -1;
   }
   indata=(unsigned char *)(cell+sizeof(cell_header_t)-8);
   datalen=header->size*128-sizeof(cell_header_t)+8;
   datalen=(datalen>>4)<<4; //multiple of 16, floor!
   enc_offset=sizeof(cell_header_t)-8;
   
  //nasty
   //circuit->sym_crypto_info[0].alg=OR_CRYPTO_ALG_BLOWFISH;
   //circuit->sym_crypto_info[1].alg=OR_CRYPTO_ALG_BLOWFISH;
   //circuit->sym_crypto_info[2].alg=OR_CRYPTO_ALG_BLOWFISH;

   circuit->sym_crypto_info[0].alg=OR_CRYPTO_ALG_AES;
   //circuit->sym_crypto_info[1].alg=OR_CRYPTO_ALG_AES;
   //circuit->sym_crypto_info[2].alg=OR_CRYPTO_ALG_AES;



   switch(circuit->state[depth]){
      case OR_CIRCUIT_STATE_DH_HELLO_RECV:
      case OR_CIRCUIT_STATE_ESTABLISHED:
         SHA1(indata+7,datalen-7,checksum);
         rvalue=memcmp(checksum,&(header->checksum),7);
         if(0==rvalue){
            //got it you are done
            return depth+1;
         }
         else{
            //try decrpting!
            //decrypt
            memcpy(buffer,header,sizeof(cell_header_t));
            switch(circuit->sym_crypto_info[depth].alg){
               case  OR_CRYPTO_ALG_BLOWFISH:
                 BF_set_key(&bf_key,16,circuit->sym_crypto_info[depth].key.key);

                 BF_cbc_encrypt(indata,
                                buffer+enc_offset,
                                datalen,
                                //&(circuit->sym_crypto_info[depth].key.bf),
                                &bf_key,
                                header->init_vector.as_uchar,
                                BF_DECRYPT);
#ifdef DEBUG_CELL_HANDLER
                fprintf(stderr,"key=\n",datalen);
                fprint_hex(stderr,circuit->sym_crypto_info[depth].key.key, 64);
                fprintf(stderr,"\n");
 

                fprintf(stderr,"iv=\n",datalen);
                fprint_hex(stderr,header->init_vector.as_uchar, 8);
                fprintf(stderr,"\n");
               
 
                fprintf(stderr,"datalen=%d\n pre=\n",datalen);
                fprint_hex(stderr,indata, 16);
                fprintf(stderr,"\n");
                fprintf(stderr," post=\n",datalen);
                fprint_hex(stderr,buffer+enc_offset, 16);
                fprintf(stderr,"\n");
#endif


                 break;
               case  OR_CRYPTO_ALG_AES:
                 AES_set_decrypt_key( circuit->sym_crypto_info[depth].key.key, 128,&aes_key);
                 memset(iv,0x00,256);
                 memcpy(iv,header->init_vector.as_uchar,8);
                 AES_cbc_encrypt(indata,
                                 buffer+enc_offset,
                                 datalen,
                                 //&(circuit->sym_crypto_info[i].key.aes.decrypt),
                                 &aes_key,
                                 //header->init_vector.as_uchar,
                                 iv,
                                 AES_DECRYPT);


#ifdef DEBUG_CELL_HANDLER
                fprintf(stderr,"Decryption:\n");
                fprintf(stderr,"iv=\n",datalen);
                fprint_hex(stderr,header->init_vector.as_uchar, 8);
                fprintf(stderr,"\n");


                fprintf(stderr,"datalen=%d\n pre=\n",datalen);
                fprint_hex(stderr,indata, 32);
                fprintf(stderr,"\n");
                fprintf(stderr," post=\n",datalen);
                fprint_hex(stderr,buffer+enc_offset, 32);
                fprintf(stderr,"\n");

                 fprintf(stderr," header=\n");
                 fprint_hex(stderr,(char *)header, 24);
                 fprintf(stderr,"\n");


#endif



                 break;
               default:
                     fprintf(stderr,"algorithm selection is mandatory!\n");
                     return -1;
            }
            //now we do the sha again.. (maybe is for us)
            SHA1(buffer+enc_offset+7,datalen-7,checksum);
            rvalue=memcmp(checksum,buffer+enc_offset,7);
            if(0==rvalue){
              //got it
              //copy overwrite input and return!
               memcpy(cell,buffer,header->size*128);
               return depth+1;
            }
            //we are here.. it was not recognized, 
            if(depth<circuit->max_level){
              //there are more levels, recurse
#ifdef VERBOSE
              fprintf(stderr,"recursing!\n");
#endif
              //return  or_circuit_decrypt_validate_cell(circuit,buffer,depth+1); 
              //this might not work!
              memcpy(cell,buffer,header->size*128);
              return  or_circuit_decrypt_validate_cell(circuit,cell,depth+1);

            }
            else{
#ifdef VERBOSE
              fprintf(stderr," Decrypt calc_check=\n");
              fprint_hex(stderr,checksum, 7);
              fprintf(stderr,"\n");

              fprintf(stderr,"forwarding?\n");
#endif
              //do overwrite 
              memcpy(cell,buffer,header->size*128);
              return 0;
            }

            
         }//ends else branch!
         break;
      default:
         // can only be local packet...
         SHA1(indata+7,datalen-7,checksum);
         rvalue=memcmp(checksum,&(header->checksum),7);
         if(0==rvalue){
            //equal, found it!
            return depth+1; 
         }
         else{
#ifdef DEBUG_CELL_HANDLER
           fprintf(stderr,"checksums do no match and should be local!\n");
           fprintf(stderr,"depth=%d,state=%d check_len= %d calc_check=\n",depth,circuit->state[depth],datalen-7);
           fprint_hex(stderr,checksum, 7);
           fprintf(stderr,"\n");
           fprintf(stderr," cell=");
           fprint_hex(stderr,cell, 30);
           fprintf(stderr,"\n");

#endif
           return -1;
         }

   }
   fprintf(stderr,"should not have gotten here!");
   return -1;
}

//------------------------------------
//-----------------------------------

//-------------------------------------------------------
//------------------------------------------------------


int send_circuit_state_packet_depth(or_circuit_t *circuit,uint8_t command,uint8_t status,unsigned char *extra,int depth){
   unsigned char buffer[2048];
   cell_header_t *cell;
   dh_hello_t  *dh;
   uint16_t lowpart;
   int32_t size;
   cell_header_t *relay_cell;
   int temp_int;
 
   if (NULL==circuit){
      fprintf(stderr,"null circuit!\n");
      return -1;
   }
   if(NULL==circuit->or_conn){
      fprintf(stderr,"null conn!\n");
      return -2;
   }
   cell=(cell_header_t *)buffer;
   cell->version=OR_CELL_VERSION;
   //what about size?
   cell->command=command;
   cell->command_status=status;
   cell->circuit_id_high=(circuit->circuit_id>>16) & 0xFF;
   cell->circuit_id_low=htons(circuit->circuit_id & 0xFFFF);

   switch(command<<12 | status <<8 |circuit->state[0]){
      case COMMAND_CREATE<<12| STATUS_REQUEST<<8 |OR_CIRCUIT_STATE_NEW:
      case COMMAND_CREATE<<12| STATUS_REQUEST<<8 |OR_CIRCUIT_STATE_DH_HELLO_SENT:
         //This assumes it is number 0!!
         //build packet         
         dh=(dh_hello_t *)(buffer+sizeof(cell_header_t));
         //generate DH if not exists,
         //if(NULL==circuit->sym_crypto_info || circuit->num_cryptos>1){
         if(circuit->num_cryptos>1){
           return -1;
         }
 
         //allocate DH if needed
         if(NULL==circuit->sym_crypto_info[0].dh){
            circuit->sym_crypto_info[0].dh=get_dh512();
 
            if(NULL==circuit->sym_crypto_info[0].dh){
                fprintf(stderr,"circuit:cannot allocate dh space!\n");
                exit(1);
            }            

            if(-1==DH_generate_key(circuit->sym_crypto_info[0].dh)){

                fprintf(stderr,"circuit:cannot generate dh key!!\n");
                exit(1);

            }
            fprintf(stderr,"cell dh allocated for: %p\n",circuit);

         }
         
        //copy dh into cell, 
         dh->key_size=htons(BN_bn2bin(circuit->sym_crypto_info[0].dh->pub_key,dh->pub_key));         
         dh->extra_len=0;
         dh->extra_type=DH_HELLO_EXTRA_TYPE_NONE;
         //now encrypt if pki!
         if(NULL==circuit->sym_crypto_info[0].rsa){
            dh->encrypted_len=0;
         }
         else{
            //will encrypt!
            dh->encrypted_len=0;
#ifdef VERBOSE
            fprintf(stderr,"doiing dh enc!\n");
            fprintf(stderr," dh local=\n");
            fprint_hex(stderr,&dh->pub_key[0], ntohs(dh->key_size));
            fprintf(stderr,"\n");
            fprintf(stderr," pre=\n");
            fprint_hex(stderr,&dh->pub_key[ntohs(dh->key_size)-DH_PKI_ENCRYPTED_LEN], DH_PKI_ENCRYPTED_LEN);      
            fprintf(stderr,"\n");
#endif
            temp_int=rsa_in_place_encrypt(circuit->sym_crypto_info[0].rsa,
                       &dh->pub_key[ntohs(dh->key_size)-DH_PKI_ENCRYPTED_LEN],
                       DH_PKI_ENCRYPTED_LEN,
                       MAX_DH_PUBLIC_SIZE-htons(dh->key_size));
            dh->encrypted_len=(uint16_t)temp_int;
            dh->encrypted_len=htons(temp_int);
            fprintf(stderr,"rval=%d enc_len=%04x\n",temp_int,(uint32_t) ntohs(dh->encrypted_len));

            //dh->encrypted_len=0;  
         }

         size=sizeof(cell_header_t)+sizeof(dh_hello_t);
         break;
      //case COMMAND_CREATE<<12| STATUS_OK<<8 |OR_CIRCUIT_STATE_NEW: 
      case COMMAND_CREATE<<12| STATUS_OK<<8 |OR_CIRCUIT_STATE_DH_HELLO_RECV:
         fprintf(stderr,"X");
         //we are sending an dh reply!!!
         dh=(dh_hello_t *)(buffer+sizeof(cell_header_t));
         //there should an allocated and initialized dh pub key!
         if(NULL==circuit->sym_crypto_info[0].dh){
           return -1;
         }
         dh->key_size=htons(BN_bn2bin(circuit->sym_crypto_info[0].dh->pub_key,dh->pub_key));
         /// need to add check, and sp some other things if pub is known
         dh->encrypted_len=0;
         size=sizeof(cell_header_t)+sizeof(dh_hello_t);
         break;
      case  COMMAND_PADDING<<12| STATUS_OK<<8 |OR_CIRCUIT_STATE_ESTABLISHED:
      case  COMMAND_PADDING<<12| STATUS_REQUEST<<8 |OR_CIRCUIT_STATE_ESTABLISHED:
         dh=(dh_hello_t *)(buffer+sizeof(cell_header_t));
         memset(dh,0x00,sizeof(cell_header_t));
         size=sizeof(cell_header_t)+sizeof(dh_hello_t);
         break;
      case COMMAND_CONNECT<<12|STATUS_REQUEST<<8|OR_CIRCUIT_STATE_ESTABLISHED:
         //this is interesting... we need to copy the input data!
         memcpy(buffer+sizeof(cell_header_t),extra,sizeof(connect_to_t));
         size=sizeof(cell_header_t)+sizeof(connect_to_t);
         break;
 
      //all the next are just commands with no data!
      case COMMAND_CONNECT<<12|STATUS_ACK <<8  |OR_CIRCUIT_STATE_ESTABLISHED:
      case COMMAND_CONNECT<<12|STATUS_DENIED<<8|OR_CIRCUIT_STATE_ESTABLISHED:
      case COMMAND_CONNECT<<12|STATUS_OK  <<8  |OR_CIRCUIT_STATE_ESTABLISHED:
         size=sizeof(cell_header_t);
#ifdef DEBUG_CELL_HANDLER
         fprintf(stderr,"sending command connect replies\n");
         fprint_hex(stderr,buffer, 20);
         fprintf(stderr,"\n");

#endif
         break;
      case COMMAND_RELAY_COMMAND<<12|STATUS_REQUEST<<8|OR_CIRCUIT_STATE_ESTABLISHED:
         print_circuit_conn_details(circuit);
         //copy the input into the buffer
         relay_cell=(cell_header_t *)extra;
         assert(relay_cell->size<=7);
         memcpy(buffer+sizeof(cell_header_t),extra,relay_cell->size*128);
         size=sizeof(cell_header_t)+relay_cell->size*128;         
         fprintf(stderr,"relay command, current_cryptos=%d\n",circuit->num_cryptos);

         break;
      default:
         fprintf(stderr,"invalid request to send circuit packet! (%d,%d,%d)\n",command,status,circuit->state[0]);
         return -1;    
   }
   //  size=ceiling(size/16)*16
   size=((size+15)>>4)<<4;

   //now make it ceiling/128
   cell->size=(size+127)>>7;

   //send cell!!
   //fprintf(stderr,"sending cell\n");

   return or_circuit_send_cell(circuit,buffer,circuit->num_cryptos); 

}


//----------------------------------------------------------------
//--------------------------------------------------------------
inline int send_circuit_state_packet(or_circuit_t *circuit,uint8_t command,uint8_t status,unsigned char *extra){
    //return 0;
    return send_circuit_state_packet_depth(circuit,command,status,extra,circuit->num_cryptos);
}

//---------------------------------------------------------------
//---------------------------------------------------------------
int handle_stream_data(or_circuit_t *circuit, unsigned char *in_cell){
    //assumes lenght of cell is verified!
    // assumes that being exit is verified too
    cell_header_t *cell_header; 
    stream_header_t *stream_header; 
    stream_extra_header_t *stream_opt;
    or_stream_t *stream;  
    //uint32_t data_size;
    or_stream_t new_stream;   
    

    cell_header=(cell_header_t*)in_cell;
    stream_header=(stream_header_t *)(in_cell+sizeof(cell_header_t));
    
    //find stream
    stream=find_stream_by_circuit_stream_id(&stream_db,circuit, ntohs(stream_header->stream_id));
    if(NULL==stream){
       if(0==global_conf.is_exit){
           fprintf(stderr,"request for nex stream not being exit!\n");
           return -1;
       }
       //create new stream!
       //cleanup
       memset(&new_stream,0x00,sizeof(or_stream_t));
       // we will do only tcp socks for now.
       new_stream.parent_circuit=circuit;
       new_stream.stream_id=ntohs(stream_header->stream_id);
       new_stream.local_ip=global_conf.default_rem_ip;
       new_stream.remote_ip=global_conf.default_rem_ip+1;
       
     
       switch(ntohs(stream_header->opt_length)>>13){
          case 0x4:
             stream_opt=(stream_extra_header_t *)(in_cell+
                                                 sizeof(cell_header_t)+
                                                sizeof(stream_extra_header_t));
             new_stream.protocol=IP_PROTO_TCP;
             new_stream.remote_port=ntohs(stream_opt->dst_port);
             do{
                new_stream.local_port=rand() | 0x8000;
                stream=find_stream_by_ip_port(&stream_db,
                                              new_stream.local_ip,
                                              new_stream.remote_ip,
                                              new_stream.local_port,
                                              new_stream.remote_port,
                                              new_stream.protocol);
             }while(NULL!=stream);
             break;
          case 0x0:
             //new_stream.local_port=rand();
             new_stream.protocol=IP_PROTO_TCP;
             new_stream.remote_port=1080;//oh no.. we need to avoid collisions!
             //should check for collisions before inserting, 
             do{
                new_stream.local_port=rand() | 0x8000;
                stream=find_stream_by_ip_port(&stream_db,
                                              new_stream.local_ip,
                                              new_stream.remote_ip,
                                              new_stream.local_port,
                                              new_stream.remote_port,
                                              new_stream.protocol);
             }while(NULL!=stream);
             break;
          default:
             return -1;
       }

       stream=insert_stream_into_db(&stream_db,&new_stream);
       assert(stream->parent_circuit==circuit);
       fprintf(stderr, "new out stream!\n");
       fprint_or_stream(stderr,stream);
    }
    //update stream
    stream->last_time=global_conf.current_time.tv_sec; 
    //now we can proceed!
    if(stream->proxy_state!=OR_STREAM_PROXY_STATE_NONE){
       return tcp_packet_transparent_proxy_handle_reverse(stream, in_cell+sizeof(cell_header_t));
    }

    return send_output_ip_packet(stream,
                                 in_cell+sizeof(cell_header_t));
};

//----------------------------------------------------------------



//-----------------------------------------------------------------------
//----------------------------------------------------------------------

//this should be in the db code?
// Yes will move it later.. 
/*
or_circuit_t *or_create_new_circuit(or_conn_t *or_conn){
    or_circuit_t *circuit=NULL;
    uint32_t circ_id;
    if(or_conn==NULL){
       return NULL;
    }
    //generate potential circuit id
    do{
      circ_id=(rand() & 0xFFFFFE) | (or_conn->initiator & 0x1);
      circuit=find_or_ins_circ_by_circ_id((circuit_db_t *)or_conn->circuit_db,circ_id);
      if(NULL==circuit){
         return NULL;
      }
    }while(circuit->state[0]!=OR_CIRCUIT_STATE_NEW);
     //there is a race condition as the find or is while atomic does not
     // tell us if the circuit has just ben issued!, need to add better mechanism
    return circuit;
}
*/

//-------------------------------------------------------------------------
//-------------------------------------------------------------------------


int or_cell_handler(or_conn_t *or_conn,unsigned char *in_cell,uint16_t in_size){
    or_circuit_t *circuit=NULL;
    or_circuit_t *out_circuit=NULL;
    unsigned char cksum[32];
    cell_header_t *header;
    int rvalue;
    //int recognized=0;
    BIGNUM *bn;
    dh_hello_t *dh=NULL;
    int32_t circuit_id;
    connect_to_t *connect_to;
    or_conn_t *conn;
    int depth=0;
    unsigned char buffer[1024];
    cell_header_t *cell_header;
    dh_hello_t *cell_dh;
    int datalen;
    DH *temp_dh;
    int enc_dec_len;

    //fprintf(stderr,"&");

    //valudate input
    if(or_conn==NULL || in_size<sizeof(cell_header_t)){
#ifdef DEBUG_CELL_HANDLER
        fprintf(stderr,"cell_handler: null orconn or badsize\n");
        fprintf(stderr,"or_conn=%u insize=%d",or_conn,in_size);
#endif
        return -1;
    }
    header=(cell_header_t *) in_cell;
    //check version    

    circuit_id=ntohs(header->circuit_id_low)|( header->circuit_id_high<<16);
   
    //search  for circuit!
    circuit=find_or_ins_circ_by_circ_id((circuit_db_t *)or_conn->circuit_db,
                                        circuit_id);
    if (NULL==circuit){
       fprintf(stderr,"cell_handler: circuit not found!!\n");
       return -1;
    }
    if(NULL==circuit->or_conn){
        circuit->or_conn=or_conn;
    }
#ifdef VERBOSE
    fprintf(stderr,"New cell: command=%d, status=%d, state=%d depth=%d\n",header->command,header->command_status, circuit->state[depth],depth);
    print_circuit_conn_details(circuit);
#endif
#ifdef DEBUG_CELL_HANDLER
    fprintf(stderr,"got cell \n");
    fprint_hex(stderr,(char *)header, 24);
    fprintf(stderr,"\n");
#endif

    if(OR_CIRCUIT_STATE_ESTABLISHED==circuit->state[0]){
       circuit->last_time=global_conf.current_time.tv_sec;
    }

    //if relay only do stuff
    if(OR_CIRCUIT_STATE_RELAY_ONLY==circuit->state[0]){
       //fprintf(stderr,"doing relay only!!");
       if(NULL==circuit->related_circuit){
         return 0;
       }
       assert(circuit->related_circuit!=NULL);
       assert(circuit->related_circuit->or_conn!=NULL);
       //just forward the message, with encryption
       //return or_circuit_send_cell(circuit->related_circuit,in_cell); 
       circuit->related_circuit->last_time=global_conf.current_time.tv_sec;  
       return or_circuit_send_forward_cell(circuit->related_circuit,in_cell);   
    }


    rvalue=or_circuit_decrypt_validate_cell(circuit,in_cell,0);
    if(0==rvalue){
        //not recognized, forward
        if(circuit->related_circuit==NULL){
          fprintf(stderr,"Packet needs forward and related is null!\n");
          //circuit should be killed here, someone is doing something nasty!
          return -1;
        }
        circuit->related_circuit->last_time=global_conf.current_time.tv_sec;
        return or_circuit_send_forward_cell(circuit->related_circuit,in_cell);
        //return 0;
    }
    if(rvalue<0){
        fprintf(stderr,"cell_handler: bad cell!\n");
        print_circuit_conn_details(circuit);
        return -1;
    }
    depth=rvalue-1;
 
    //change it for a while.. this is very shaky!
    if(circuit->state[depth]==OR_CIRCUIT_STATE_ESTABLISHED){
       switch(header->command  << 8| header->command_status ){
             case  COMMAND_CONNECT       <<8 | STATUS_REQUEST:
             case  COMMAND_RELAY_COMMAND <<8 | STATUS_REQUEST:
             case  COMMAND_STREAM_DATA   <<8 | STATUS_REQUEST:
             case  COMMAND_PADDING       <<8 | STATUS_REQUEST:
                 break;
             default:
                 depth++;
                 break;  
         }
    }    
  
    

    //else, the packet is for us!!!
    //do a single switch for all transformations!
    switch(header->command  <<12| header->command_status <<8 | circuit->state[depth]){
         case COMMAND_CREATE <<12| STATUS_REQUEST <<8| OR_CIRCUIT_STATE_NEW:
         case COMMAND_CREATE <<12| STATUS_REQUEST <<8| OR_CIRCUIT_STATE_DH_HELLO_RECV:
  
            fprintf(stderr,"Do something!!!!\n");
            //verify size!!!
            if(in_size<sizeof(cell_header_t)+sizeof(dh_hello_t)){
               return -1;
            }
            dh=(dh_hello_t *)(in_cell+sizeof(cell_header_t));
            //allocate dh and generate pub key if not exists!!
            if(NULL==circuit->sym_crypto_info[depth].dh){
                fprintf(stderr,"about to getdh, depth=%d dh[%p]\n",
                                        depth,
                                        &circuit->sym_crypto_info[depth].dh);
                
                //circuit->sym_crypto_info[depth].dh=get_dh512(); 
                temp_dh=get_dh512();
                fprintf(stderr,"after dh params!\n");
                circuit->sym_crypto_info[depth].dh=temp_dh;
                fprintf(stderr,"after dh assign!\n");
                if(NULL==circuit->sym_crypto_info[depth].dh){
                    fprintf(stderr,"cell_handler: cannot allocate_dh\n");
                    exit(1);
                }
                if(-1==DH_generate_key(circuit->sym_crypto_info[depth].dh)){
                  fprintf(stderr,"cell_handler:cannot generate dh key!!\n");
                  exit(1);

                }

            }
            fprintf(stderr,"DH generated!\n");
            //now generate secret!!!            
          
            fprintf(stderr,"enc_len=%d\n",ntohs(dh->encrypted_len)); 
            if(0!=dh->encrypted_len ){
               //do inplace decrpytion
                fprintf(stderr,"doing dh decryption!");
                fprintf(stderr,"got enc:\n");
                fprint_hex(stderr,&dh->pub_key[ntohs(dh->key_size)-DH_PKI_ENCRYPTED_LEN], DH_PKI_ENCRYPTED_LEN);
                fprintf(stderr,"\n");
                enc_dec_len=rsa_in_place_decrypt(global_conf.rsa_key,
                                 &dh->pub_key[ntohs(dh->key_size)-DH_PKI_ENCRYPTED_LEN],
                           ntohs(dh->encrypted_len),
                           MAX_DH_PUBLIC_SIZE-ntohs(dh->key_size));
                fprintf(stderr,"dh=\n");
                fprint_hex(stderr,&dh->pub_key[0], ntohs(dh->key_size));
                fprintf(stderr,"\n");
            }
            bn=BN_new();
            assert(bn!=NULL);
            BN_bin2bn(dh->pub_key,ntohs(dh->key_size),bn);
            //now calculate secret
           //rvalue=DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
            fprintf(stderr,"before computing key\n");
            rvalue=DH_compute_key(circuit->sym_crypto_info[depth].key.key,bn,circuit->sym_crypto_info[depth].dh);
            fprintf(stderr,"after computing key\n");
            BN_free(bn);
            if(-1==rvalue){
                fprintf(stderr,"hl: Error computing dh key!\n");
                return -1;
            }
#ifdef VERBOSE
            fprintf(stderr,"key_len=%d\n",rvalue);
            fprint_hex(stderr,circuit->sym_crypto_info[depth].key.key,rvalue);
            fprintf(stderr,"\n");
#endif

            //send packet
            //return 
            circuit->state[depth]=OR_CIRCUIT_STATE_DH_HELLO_RECV; 
//
            
            return send_circuit_state_packet(circuit,COMMAND_CREATE,STATUS_OK,NULL);
            //return 0;
            break;
         //case COMMAND_CREATE <<12| STATUS_OK <<8| OR_CIRCUIT_STATE_NEW:
        // case COMMAND_CREATE <<12| STATUS_OK <<8| OR_CIRCUIT_STATE_CONNECTING:
         case COMMAND_CREATE <<12| STATUS_OK <<8| OR_CIRCUIT_STATE_DH_HELLO_SENT:
            fprintf(stderr,"here again");
            //verify size!!!
            if(in_size<sizeof(cell_header_t)+sizeof(dh_hello_t)){
               return -1;
            }
            dh=(dh_hello_t *)(in_cell+sizeof(cell_header_t));
            //allocate dh and generate pub key if not exists!!
            if(NULL==circuit->sym_crypto_info[depth].dh){
               
               fprintf(stderr,"Null dh? wtf! circ=%p",circuit);
               return -1;
            }
  /*
            fprintf(stderr,"recv dh got pubkey: len=%u\n",ntohs(dh->key_size));
            fprint_hex(stderr,dh->pub_key,ntohs(dh->key_size));
            fprintf(stderr,"\n");
  */
            //WE SHOULD CHECK THE EXTRA DATA!!!!!

            //we can compute the key
            bn=BN_new();
            BN_bin2bn(dh->pub_key,ntohs(dh->key_size),bn);
            //now calculate secret
           //rvalue=DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
            rvalue=DH_compute_key(circuit->sym_crypto_info[depth].key.key,bn,circuit->sym_crypto_info[depth].dh);
            BN_free(bn);
            if(-1==rvalue){
                fprintf(stderr,"hl: Error computing dh key!\n");
                return -1;
            }
            //BF_set_key(&circuit->sym_crypto_info[depth].key.bf,
            //            16,circuit->sym_crypto_info[depth].key.key);
#ifdef VERBOSE
            fprintf(stderr,"key_len=%d\n",rvalue);
            fprint_hex(stderr,circuit->sym_crypto_info[depth].key.key,rvalue);
            fprintf(stderr,"\n");
#endif
            circuit->state[depth]=OR_CIRCUIT_STATE_ESTABLISHED;
            circuit->sym_crypto_info[depth].alg=OR_CRYPTO_ALG_AES;
            circuit->num_cryptos=depth+1;
            //need to encapsulate if needed!
            fprintf(stderr,"about to send padding, depth=%d",depth);
            return send_circuit_state_packet(circuit,COMMAND_PADDING,STATUS_OK,NULL);
            //return send_circuit_state_packet_depth(circuit,COMMAND_RELAY_COMMAND,STATUS_REQUEST,buffer,depth+1);

            return 0;
            break;
 
         //next: nop
         case  COMMAND_PADDING <<12| STATUS_OK<<8| OR_CIRCUIT_STATE_ESTABLISHED:
         case  COMMAND_PADDING <<12| STATUS_OK<<8| OR_CIRCUIT_STATE_DH_HELLO_RECV:

            circuit->state[depth]=OR_CIRCUIT_STATE_ESTABLISHED;
            circuit->sym_crypto_info[depth].alg=OR_CRYPTO_ALG_AES;
            circuit->packet_count[depth]++;
            circuit->num_cryptos=1;
            fprintf(stderr,"got padding! circ=%p\n",circuit);
            return 0; //
            break;
       
       /*BEARE of fallTHROUGH!!!*/
       /*
       case COMMAND_CONNECT <<12| STATUS_REQUEST<<8| OR_CIRCUIT_STATE_DH_HELLO_RECV:
            fprintf(stderr,"warning padding lost?\n ");
            circuit->state[depth]=OR_CIRCUIT_STATE_ESTABLISHED;
            circuit->sym_crypto_info[depth].alg=OR_CRYPTO_ALG_AES;
            circuit->packet_count[depth]++;
            circuit->num_cryptos=1;
       */

       case COMMAND_CONNECT <<12| STATUS_REQUEST<<8| OR_CIRCUIT_STATE_ESTABLISHED:
            //should validate that depth==0    

            fprintf(stderr,"got connect request, depht=%d!",depth);
            //are we connected to that place?
            if(circuit->related_circuit!=NULL){
               fprintf(stderr,"has related circuit!\n");
               //check if related conn is to the same place
               if(circuit->related_circuit->or_conn==NULL){
                  fprintf(stderr,"WTF no or conn of related!!\n");
                  return -1;
               }
               connect_to=(connect_to_t *)(in_cell+sizeof(cell_header_t));
               if(circuit->related_circuit->or_conn->remote_ip!=
                             ntohl(connect_to->ipv4_addr) ||
                 circuit->related_circuit->or_conn->remote_port!=
                             ntohs(connect_to->port)){
                   fprintf(stderr,"attempting to connect"
                                  " to another system, not valid!!\n");
                   fprintf(stderr,"related_or_conn_ip=%u"
                                  " related_or_conn_port=%u", circuit->related_circuit->or_conn->remote_ip,circuit->related_circuit->or_conn->remote_port);
                   fprintf(stderr,"request_ip=%u"   
                                 " request_port=%u\n", 
                                   ntohl(connect_to->ipv4_addr),ntohs(connect_to->port));
                   fprintf(stderr,"depth=%u\n",depth);
                   //send rejected!
                   return send_circuit_state_packet(circuit,COMMAND_CONNECT,STATUS_DENIED,NULL);
               }
               conn=circuit->related_circuit->or_conn;
               //else they check up
               if(conn->state==CONN_STATE_ESTABLISHED){
                   circuit->related_circuit->state[0]=OR_CIRCUIT_STATE_RELAY_ONLY;
                   return send_circuit_state_packet(circuit,COMMAND_CONNECT,STATUS_OK,NULL);
               }
               else{
                  //retry conn
                  //send ACK
                  fprintf(stderr,"not done yet!!,state=%d\n, conn=%p",conn->state,conn);
                  return 0;
               }
            }
            
            //we are here, there is no related circuit...
            connect_to=(connect_to_t *)(in_cell+sizeof(cell_header_t));
            conn=find_or_ins_conn_by_src_dst(&conn_db,
                                            ntohl(connect_to->ipv4_addr),
                                            ntohs(connect_to->port));
            assert(conn!=NULL);

            if(conn->state==CONN_STATE_NEW){
               // this is a new one!
               conn->state=CONN_STATE_CAPA_SENT;
               conn->initiator=1;
               fprintf(stderr,"sending conn request!\n");
               //fprintf(stderr,"oldconn=%x, newconn=%x",circuit->or_conn,conn);
               //fprintf(stderr,"oldport=%d, newport=%d",circuit->or_conn->remote_port,conn->remote_port);
               rvalue=send_link_state_packet(conn, LINK_PK_TYPE_CAPAHELLO);                 }
            //create new circuit.. done AFTER initiator is potentially set!
            out_circuit=or_create_new_circuit(conn);
            fprintf(stderr,"conn  %p  state=%d\n",conn,conn->state);
            assert(out_circuit!=NULL);
            circuit->related_circuit=out_circuit;
            out_circuit->related_circuit=circuit;
            //and just in case:
            out_circuit->or_conn=conn;
            print_circuit_conn_details(circuit);
            print_circuit_conn_details(out_circuit);

            if(conn->state==CONN_STATE_ESTABLISHED){
               // set out circuit state to relay! and send ok
               out_circuit->state[0]=OR_CIRCUIT_STATE_RELAY_ONLY;
               fprintf(stderr,"out circuit, relay_only?\n");
               print_circuit_conn_details(out_circuit);
               //send ok
               return send_circuit_state_packet(circuit,COMMAND_CONNECT,STATUS_OK,NULL);
            }
            else{
               //send ack
               return send_circuit_state_packet(circuit,COMMAND_CONNECT,STATUS_ACK,NULL);

            }
            return 0;
            break;
         
         //case COMMAND_CONNECT <<12| STATUS_ACK<<8| OR_CIRCUIT_STATE_ESTABLISHED:
         case COMMAND_CONNECT<<12 |STATUS_ACK <<8 |OR_CIRCUIT_STATE_NEW:
            //there needs to be  check on the depth..
            circuit->state[depth]=OR_CIRCUIT_STATE_CONNECTING;
            break;

         //cviecco, march 5 2008 noon, fallthrough, BEWARE!
         case COMMAND_CONNECT<<12 |STATUS_OK <<8 |OR_CIRCUIT_STATE_NEW:
            circuit->state[depth]=OR_CIRCUIT_STATE_CONNECTING;
            //break;
         case COMMAND_CONNECT<<12 |STATUS_OK <<8 | OR_CIRCUIT_STATE_CONNECTING:
            //send new connection!...
            if(depth==0){
              return -1;
            }            
            //send new in relay command!
            fprintf(stderr,"sould send a relay command: create here!\n");
            //build dh parameters, should be moved to a func
            //allocate dh and generate pub key if not exists!!
            if(NULL==circuit->sym_crypto_info[depth].dh){
                circuit->sym_crypto_info[depth].dh=get_dh512();
                if(NULL==circuit->sym_crypto_info[depth].dh){
                    fprintf(stderr,"cell_handler: cannot allocate_dh\n");
                    exit(1);
                }
                if(-1==DH_generate_key(circuit->sym_crypto_info[depth].dh)){
                  fprintf(stderr,"cell_handler:cannot generate dh key!!\n");
                  exit(1);

                }

            }
            cell_header=(cell_header_t *)buffer; 
            cell_dh=(dh_hello_t *)(buffer+sizeof(cell_header_t));
            //fill dh,
            cell_dh->key_size=htons(BN_bn2bin(circuit->sym_crypto_info[depth].dh->pub_key,cell_dh->pub_key));
            cell_dh->encrypted_len=0;

            //fill cell header
            cell_header->version=OR_CELL_VERSION;
            cell_header->size=((sizeof(cell_header_t)+sizeof(dh_hello_t)+127)>>7);
            cell_header->init_vector.as_uint64=rand();//this is so bad! 
            cell_header->command= COMMAND_CREATE;
            cell_header->command_status=STATUS_REQUEST; 
            //circuit_id is left alone
            //compute chekcsum            
            datalen=cell_header->size*128-sizeof(cell_header_t)+8;
 
            //now align the datalen to the 16 bytes!
            datalen=(datalen+15>>4)<<4;
            //datalen=header->size<<7;

            //calculate the sha and write it!!!
            //SHA1(indata+7,datalen-7,header->checksum.as_uchar);
            SHA1(buffer+sizeof(cell_header_t)-1,datalen-7,cksum);
            //memset(cell_header->checksum.as_uchar,0xFF,7);
            memcpy(cell_header->checksum.as_uchar,cksum,7);
#ifdef DEBUG_CELL_HANDLER
            fprintf(stderr,"relay command:\n");
            fprintf(stderr,"size=%d, key_size=%d cksize=%d\n",cell_header->size,ntohs(cell_dh->key_size),datalen-7 );
            fprintf(stderr,"relay ck:\n");
            fprint_hex(stderr,cksum,7);
            fprintf(stderr,"\n");
            fprint_hex(stderr,buffer,30);
            fprintf(stderr,"\n");
#endif
            //now we send the buffer
            return send_circuit_state_packet(circuit,COMMAND_RELAY_COMMAND,STATUS_REQUEST,buffer);
            break;


         case COMMAND_RELAY_COMMAND<<12 |STATUS_REQUEST <<8 |OR_CIRCUIT_STATE_ESTABLISHED:
            //this is easy,sort of..
            //start with sanity checks
            if(NULL==circuit->related_circuit){
                 fprintf(stderr,"cell handler: relay_command: no related circuit\n");
                 return -1;
            } 
            if(circuit->related_circuit->state[0]!=OR_CIRCUIT_STATE_RELAY_ONLY &&
               circuit->related_circuit->state[0]!=OR_CIRCUIT_STATE_ESTABLISHED){
               fprintf(stderr,"cell handler: relay_command: bad relay circuit state state=%d\n",circuit->related_circuit->state[0]);
               return -1;
            };
            //now send via related!
            return or_circuit_send_relay_command_cell(circuit->related_circuit,in_cell+sizeof(cell_header_t));
             
            break;           

    
         case COMMAND_CREATE <<12| STATUS_OK <<8| OR_CIRCUIT_STATE_CONNECTING:
            fprintf(stderr,"here again_connecting %d!",depth);
            //verify size!!!
            if(in_size<sizeof(cell_header_t)+sizeof(dh_hello_t)){
               return -1;
            }
            dh=(dh_hello_t *)(in_cell+sizeof(cell_header_t));
            //allocate dh and generate pub key if not exists!!
            if(NULL==circuit->sym_crypto_info[depth].dh){

               fprintf(stderr,"Null dh? wtf! circ=%p",circuit);
               return -1;
            }

            //fprintf(stderr,"recv dh got pubkey: len=%u\n",ntohs(dh->key_size));
            //fprint_hex(stderr,dh->pub_key,ntohs(dh->key_size));
            //fprintf(stderr,"\n");
            
            //decrypt key if needed!!
            fprintf(stderr,"enc_len=%d\n",ntohs(dh->encrypted_len));
            if(0!=dh->encrypted_len ){
               //do inplace decrpytion
                fprintf(stderr,"doing dh decryption!");
                fprintf(stderr,"got enc:\n");
                fprint_hex(stderr,&dh->pub_key[ntohs(dh->key_size)-DH_PKI_ENCRYPTED_LEN], DH_PKI_ENCRYPTED_LEN);
                fprintf(stderr,"\n");
                enc_dec_len=rsa_in_place_decrypt(global_conf.rsa_key,
                                 &dh->pub_key[ntohs(dh->key_size)-DH_PKI_ENCRYPTED_LEN],
                           ntohs(dh->encrypted_len),
                           MAX_DH_PUBLIC_SIZE-ntohs(dh->key_size));
                fprintf(stderr,"dh=\n");
                fprint_hex(stderr,&dh->pub_key[0], ntohs(dh->key_size));
                fprintf(stderr,"\n");
            }

            //we can compute the key
            bn=BN_new();
            assert(bn!=NULL);
            BN_bin2bn(dh->pub_key,ntohs(dh->key_size),bn);
            //now calculate secret
           //rvalue=DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
            rvalue=DH_compute_key(circuit->sym_crypto_info[depth].key.key,bn,circuit->sym_crypto_info[depth].dh);
            BN_free(bn);
            if(-1==rvalue){
                fprintf(stderr,"hl: Error computing dh key!\n");
                return -1;
            }

#ifdef DEBUG_CELL_HANDLER
            fprintf(stderr,"key_len=%d\n",rvalue);
            fprint_hex(stderr,circuit->sym_crypto_info[depth].key.key,rvalue);
            fprintf(stderr,"\n");
#endif
            circuit->state[depth]=OR_CIRCUIT_STATE_ESTABLISHED;
            circuit->sym_crypto_info[depth].alg=OR_CRYPTO_ALG_AES;
            //circuit->num_cryptos=depth;
            //circuit->num_cryptos=1;             

            //need to encapsulate if needed!
            //return send_circuit_state_packet(circuit,COMMAND_PADDING,STATUS_OK,NULL);

            cell_header=(cell_header_t *)buffer;
            cell_header=(cell_header_t *)buffer;
            cell_dh=(dh_hello_t *)(buffer+sizeof(cell_header_t));
            //fill cell header
            cell_header->version=OR_CELL_VERSION;
            cell_header->size=((sizeof(cell_header_t)+sizeof(dh_hello_t)+127)>>7);
            cell_header->init_vector.as_uint64=rand();//this is so bad!
            cell_header->command= COMMAND_PADDING;
            cell_header->command_status=STATUS_OK;
            //circuit_id is left alone
            //compute chekcsum
            datalen=cell_header->size*128-sizeof(cell_header_t)+8;

            //now align the datalen to the 16 bytes!
            datalen=(datalen+15>>4)<<4;

            //calculate the sha and write it!!!
            SHA1(buffer+sizeof(cell_header_t)-1,datalen-7,cksum);
            memcpy(cell_header->checksum.as_uchar,cksum,7);
#ifdef DEBUG_CELL_HANDLER
            fprintf(stderr,"relay command:\n");
            fprintf(stderr,"size=%d, key_size=%d cksize=%d\n",cell_header->size,ntohs(cell_dh->key_size),datalen-7 );
            fprintf(stderr,"relay ck:\n");
            fprint_hex(stderr,cksum,7);
            fprintf(stderr,"\n");
            fprint_hex(stderr,buffer,30);
            fprintf(stderr,"\n");
#endif
            fprintf(stderr,"about to send padding on relay, depth=%d\n",depth);
            //now we send the buffer
            return send_circuit_state_packet_depth(circuit,COMMAND_RELAY_COMMAND,STATUS_REQUEST,buffer,depth);
            break;
         case COMMAND_STREAM_DATA<<12 |STATUS_REQUEST <<8 |OR_CIRCUIT_STATE_ESTABLISHED:
            //fprintf(stderr,"got stream data\n");
            //check if exit
            //if(global_conf.is_exit==0){
               //fprintf(stderr,"request for stream out not being exit!\n");
               //return -1;
            //}
            return handle_stream_data(circuit, in_cell);           
            break;
         case  COMMAND_PADDING <<12| STATUS_REQUEST<<8| OR_CIRCUIT_STATE_ESTABLISHED:
             return send_circuit_state_packet(circuit,COMMAND_PADDING,STATUS_OK,NULL);   
             break;
         case  COMMAND_PADDING <<12| STATUS_OK<<8| OR_CIRCUIT_STATE_NEW:
             return 0;
             break; 
         default:
            fprintf(stderr,"cell_handler bad case?: %d: %d %u depth:%d circuit=%p\n",header->command, header->command_status,circuit->state[depth],depth,circuit);
            return -1;         

    }     
    //we should not be arriving here!
    return -1;
}



