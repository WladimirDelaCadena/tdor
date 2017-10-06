/*
**  (C) 2007-2008 Camilo Viecco.  All rights reserved.
**  PART of this file contains stuff copied from the curl examples!
**
**  This file is part of Tdor, and is subject to the license terms in the
**  LICENSE file, found in the top level directory of this distribution. If you
**  did not receive the LICENSE file with this file, you may obtain it by
**  contacting the authors listed above. No part of Tdor, including this file,
**  may be copied, modified, propagated, or distributed except according to the
**  terms described in the LICENSE file.
*/



#include "ds_comm.h"
#include "tor-udp.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <openssl/bn.h>


extern const global_conf_t global_conf;
extern const bw_queue_state_t output_queue;


int init_ds_comm(){
  int rvalue;
  rvalue=curl_global_init(CURL_GLOBAL_NOTHING);  
  if(0!=rvalue){
    fprintf(stderr,"cannot initialize curl");
  }
  return rvalue;
}

int upload_server_descriptor(){
  //this will be a simple post!
  CURL *curl;
  CURLcode res;
  int rvalue=-1;

  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char buf[] = "Expect:";
  char public_descriptor[1024];
  char *pube;
  char *pubn;  
  struct in_addr pub_addr;
  char *string_ip;
  char string_ip2[32];

  pub_addr.s_addr=htonl(global_conf.advertised_ipv4);
  string_ip=inet_ntoa(pub_addr);


 
  pube=BN_bn2hex(global_conf.rsa_key->e);
  pubn=BN_bn2hex(global_conf.rsa_key->n);

 

   snprintf(public_descriptor,1024, "%s %d %d %d %d %s,%s",
                              string_ip,
                              global_conf.bind_port,
                              global_conf.is_client,
                              global_conf.is_exit,
                              output_queue.kbps,
                              pube,
                              pubn);

   OPENSSL_free(pube);
   OPENSSL_free(pubn);
/*
   //need to fix, to write the bw of the system!
   //now the pki is written!
   BN_print_fp(stream,conf->rsa_key->e);
   fprintf(stream,",");
   BN_print_fp(stream,conf->rsa_key->n);

*/


   /* Fill in the submit field too, even if this is rarely needed */
   curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "com",
               CURLFORM_COPYCONTENTS, "upload",
               CURLFORM_END);

   curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "version",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);

   curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "public_desc",
               CURLFORM_COPYCONTENTS, public_descriptor,
               CURLFORM_END);
  

  curl = curl_easy_init();
   headerlist = curl_slist_append(headerlist, buf);
  if(curl) {
    /* what URL that receives this POST */

    curl_easy_setopt(curl, CURLOPT_URL, "http://nettrust1.ucs.indiana.edu/perl/tdor-ds.pl");
    //if ( (argc == 2) && (!strcmp(argv[1], "noexpectheader")) )
      // only disable 100-continue header if explicitly requested //
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    
    //set ip to be the bind ip!
    pub_addr.s_addr=htonl(global_conf.bind_ipv4);
    string_ip=inet_ntoa(pub_addr);
    memset(string_ip2,0x00,32);
    strncpy(string_ip2,string_ip,31);
    //fprintf(stderr,"curlopt interface=%s\n",string_ip);
    if(0!=global_conf.bind_ipv4){
      curl_easy_setopt(curl,CURLOPT_INTERFACE,string_ip2);
    }

    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree(formpost);
    /* free slist */
    curl_slist_free_all (headerlist);
    rvalue=0;
  }
  else{
    //cleanup header list?
     /* then cleanup the formpost chain */
    curl_formfree(formpost);
    /* free slist */
    curl_slist_free_all (headerlist);
  }
  return rvalue;
}

static size_t curl_write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  int written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}


int dowload_server_lists(){
  CURL *curl_handle;
  static const char *headerfilename = "/tmp/head.out";
  FILE *headerfile;
  static const char *bodyfilename = "/tmp/body.out";
  FILE *bodyfile;

  curl_global_init(CURL_GLOBAL_ALL);

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* set URL to get */
  //curl_easy_setopt(curl_handle, CURLOPT_URL, "http://curl.haxx.se");
  curl_easy_setopt(curl_handle, CURLOPT_URL, "http://nettrust1.ucs.indiana.edu/perl/tdor-ds.pl?com=list;version=1");

  /* no progress meter please */
  curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

  /* send all data to this function  */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write_data);

  /* open the files */
  headerfile = fopen(headerfilename,"w");
  if (headerfile == NULL) {
    curl_easy_cleanup(curl_handle);
    return -1;
  }
  bodyfile = fopen(bodyfilename,"w");
  if (bodyfile == NULL) {
    curl_easy_cleanup(curl_handle);
    return -1;
  }
  /* we want the headers to this file handle */
  curl_easy_setopt(curl_handle,   CURLOPT_WRITEHEADER, headerfile);

  /*
   * Notice here that if you want the actual data sent anywhere else but
   * stdout, you should consider using the CURLOPT_WRITEDATA option.  */
   curl_easy_setopt(curl_handle,   CURLOPT_WRITEDATA, bodyfile);


  /* get it! */
  curl_easy_perform(curl_handle);

  /* close the header file */
  fclose(headerfile);
  fclose(bodyfile);

  /* cleanup curl stuff */
  curl_easy_cleanup(curl_handle);

  return 0;


}


void *directory_server_status_updater(void *in_val){
 struct timespec delay;

 //forever loop
 while(1==1){
      upload_server_descriptor();
      delay.tv_sec=300;
      delay.tv_nsec=30000000;
      nanosleep(&delay,NULL);
   
 }

}


