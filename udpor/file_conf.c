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

#include "file_conf.h"
#include "tor-udp.h"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

extern global_conf_t global_conf;

char *conf_key[] ={
/* 0*/      "bandwidth",
/* 1*/      "is_client",
/* 2*/      "is_exit",
/* 3*/      "port",
/* 4*/      "rsa_n",
/* 5*/      "rsa_e",
/* 6*/      "rsa_d",
/* 7*/      "rsa_p",
/* 8*/      "rsa_q",
/* 9*/      "rsa_dmp1",
/*10*/      "rsa_dmq1",
/*11*/      "rsa_iqmp",
};

int  name_to_num(char *in_conf_key){
   int i;
   for(i=0;i<12;i++){
  
      if (0==strncmp(in_conf_key,conf_key[i],24)){
         return i;
      }

   }

   return -1;

}

int load_conf_line(char *line){
   //split the line
   int num=0;
   char *key;
   char *value;
   char *state;
   
   key=strtok_r(line,"= ",&state);
   if(NULL==key){
     return -1;
   }
   value=strtok_r(NULL,"= ",&state);
   if(NULL==value){
     return -1;
   }
 
   num=name_to_num(key);   

   switch(num){
       case 0:
          break;
       case 4:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->n,value);
          break;
       case 5:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->e,value);
          break;
       case 6:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->d,value);
          break;
       case 7:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->p,value);
          break;
       case 8:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->q,value);
          break;
       case 9:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->dmp1,value);
          break;
       case 10:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->dmq1,value);
          break;
       case 11:
          //should we check the stuff?
          BN_hex2bn(&global_conf.rsa_key->iqmp,value);
          break;

   }  
   return 0;   
 
}


int load_conf_file(const char *filename){
   FILE *file;
   char in_line[2048];
 
   file=fopen(filename,"r");
   if(NULL==file){
       return -1;
   }
   if(NULL==global_conf.rsa_key){
       global_conf.rsa_key=RSA_new();
       if(NULL==global_conf.rsa_key){
          perror("failed to allocate memory for rsa!\n");
          exit(EXIT_FAILURE);
       }
   }

   while(NULL!=fgets(in_line,2047,file)){
      
       load_conf_line(in_line);
   }
   
   fclose(file);
   //now we check that the rsa contains basic data!
  if(NULL==global_conf.rsa_key->n ||
     NULL==global_conf.rsa_key->e ||
     NULL==global_conf.rsa_key->d ||
     NULL==global_conf.rsa_key->p ||
     NULL==global_conf.rsa_key->q ){
       return -2;
  }
 
   return 0;
}

int save_conf_file(const char *filename){
   int i;
   char *empty="";
   char *hex_val;
   char out_line[2048];
   FILE *file;   

   file=fopen(filename,"w");
   if(NULL==file){
      perror("canno open file to write!\n");
      exit(EXIT_FAILURE);
   } 
      


   /*Do rsa*/
   if (NULL==global_conf.rsa_key){
       global_conf.rsa_key=RSA_new();
       global_conf.rsa_key=RSA_generate_key(1024,RSA_F4,NULL,NULL);
       if(NULL==global_conf.rsa_key){
           perror("failed to allocate memory for rsa!\n");
           exit(EXIT_FAILURE);
       }
   }
 


   for(i=4;i<12;i++){
      hex_val=empty;
      switch(i){
         case 4:
            hex_val=BN_bn2hex(global_conf.rsa_key->n);
            break;
         case 5:
            hex_val=BN_bn2hex(global_conf.rsa_key->e);
            break;
         case 6:
            hex_val=BN_bn2hex(global_conf.rsa_key->d);
            break;
         case 7:
            hex_val=BN_bn2hex(global_conf.rsa_key->p);
            break;
         case 8:
            hex_val=BN_bn2hex(global_conf.rsa_key->q);
            break;
         case 9:
            hex_val=BN_bn2hex(global_conf.rsa_key->dmp1);
            break;
         case 10:
            hex_val=BN_bn2hex(global_conf.rsa_key->dmq1);
            break;
         case 11:
            hex_val=BN_bn2hex(global_conf.rsa_key->iqmp);
            break;

      
      }
      snprintf(out_line,2047,"%s=%s\n",conf_key[i],hex_val);
      fprintf(file,"%s",out_line);
   }
   fclose(file); 
   return 0;
}

int update_conf_file(char *filename){
  //not implemented
  return 0;
}

