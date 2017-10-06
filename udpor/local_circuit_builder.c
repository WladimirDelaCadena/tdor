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
#include "cell_handler.h"
//#include "circuit_crypto.h"
#include "internal_db.h"
#include "link_conn.h"
#include "local_circuit_builder.h"
#include <netinet/in.h>
#include "cell_handler.h"
#include "udp_transport.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <time.h>
#include <pthread.h>
#include <openssl/bn.h>
#include "util.h"
#include <openssl/rsa.h>

#include <ds_comm.h>
#include <assert.h>

#define ROUTER_DB_FILENAME "router_list.txt"

extern conn_db_t conn_db;
extern global_conf_t global_conf;

router_db_t router_db;


int print_router_data(router_data_t *in_router){
   char string_ip[64];
   snprintf(string_ip,63,"%u.%u.%u.%u",in_router->ip>>24,(in_router->ip)>>16 &0xFF,(in_router->ip>>8) & 0xFF,(in_router->ip &0xFF));

      
   fprintf(stderr,"%s %u %d %d %d %u %u %u ", string_ip,
                                          in_router->ip,
                                          in_router->udp_port,
                                          in_router->tcp_port,
                                          in_router->is_exit,in_router->bw,
                                          in_router->rsa.e_size,
                                          in_router->rsa.n_size);
   fprint_hex(stderr,in_router->rsa.n,4);
   return fprintf(stderr,"\n");
   return 0;
}

//this is very inefficient!!
int process_router_line(char *line, router_data_t *in_router){
   char *token;
   char *search =" ";
   char *last;
   router_data_t router;
   struct in_addr addr;
   BIGNUM *bn;   

   memset(in_router,0x00,sizeof(router_data_t));


   if(line[0]=='#'){
      return -1;
   }

   //search for ip
   token = (char *)strtok_r(line,
               search,
               &last);
   if(NULL==token){return -1;};
   inet_aton(token,&addr);
   router.ip=ntohl(addr.s_addr);
 
   token = (char *)strtok_r((char *)NULL,search, &last);
   if(NULL==token){return -1;};
   router.udp_port=atoi(token);
   
   token = (char *)strtok_r((char *)NULL,search, &last);
   if(NULL==token){return -1;};
   router.tcp_port=atoi(token);

   token = (char *)strtok_r((char *)NULL,search, &last);
   if(NULL==token){return -1;};
   router.is_exit=atoi(token);

   token = (char *)strtok_r((char *)NULL,search, &last);
   if(NULL==token){return -1;};
   router.bw=atoi(token);

   //now we read search for the exponent!
   token = (char *)strtok_r((char *)NULL,",", &last);
   if(NULL==token){return -1;};
   bn=BN_new();
   router.rsa.rsa=RSA_new();
   if(NULL==bn || NULL==router.rsa.rsa){return -1;};
   router.rsa.e_size=BN_hex2bn(&bn,token);
   BN_bn2bin(bn,router.rsa.e);

   if(NULL==router.rsa.rsa->e){
      router.rsa.rsa->e=BN_new();
      if(NULL==router.rsa.rsa->e){
        exit(EXIT_FAILURE);
      }
   }  
   if(NULL==BN_copy(router.rsa.rsa->e,bn)){
      return -1;
   }

   token = (char *)strtok_r((char *)NULL,search, &last);
   if(NULL==token){BN_free(bn);return -1;};

   router.rsa.n_size=BN_hex2bn(&bn,token);
   BN_bn2bin(bn,router.rsa.n);

   if(NULL==router.rsa.rsa->n){
      router.rsa.rsa->n=BN_new();
      if(NULL==router.rsa.rsa->n){
        exit(EXIT_FAILURE);
      }
   }

   if(NULL==BN_copy(router.rsa.rsa->n,bn)){
      return -1;
   }
   
   BN_free(bn); 
   //now we read transform as pure rsa
   

   //print_router_data(&router);  
   memcpy(in_router,&router,sizeof(router_data_t)); 
   return 0;
   
}

int load_router_db_from(char *filename){
   char line[ROUTER_LINE_MAX];
   FILE *router_file;
   //fprintf(stderr,"router file: %s" , filename);

   int i=0;
   int rvalue;

   //download router list!
   //rvalue=dowload_server_lists();


   router_file=fopen(filename,"r");
   if(NULL==router_file){
     perror("cannot open router_db\n");
     exit(1);
     }
 
   while ((fgets(line, ROUTER_LINE_MAX, router_file) != NULL) && (i<MAX_ROUTERS)) {
     //fprintf(stderr,"line: %s",line);
     rvalue=process_router_line(line,&(router_db.router[i]));
     if(rvalue>=0){i++;}         
     }
  router_db.num_routers=i;
  for(i=0;i<router_db.num_routers;i++)
    print_router_data(&(router_db.router[i])); 
  fclose(router_file);               
  return router_db.num_routers;
}

int load_router_db(){
   int rvalue=-1;
   //download router list!
   //rvalue=dowload_server_lists();
   fprintf(stdout,"value r: %i",rvalue);
   if(rvalue>=0){
      rvalue=load_router_db_from("/tmp/body.out");
      }
   if(rvalue<0){
      fprintf(stderr,"cannot load from server, loading local db\n");
      rvalue=load_router_db_from(ROUTER_DB_FILENAME);
      }
   if(rvalue<0){
      perror("loaded db is too small or cannot open file, aborting!\n");
      exit(1);
   }
   return rvalue;
}

int client_select_ciruit_path(int numhops,router_data_t **path, int t_circuit){
    //this is a silly selection path 
    // go linearly over the router db!!
    int i,j;
    int exit_index=0;
    int num_exits=0;
    int selected;
    int rvalue;
    for(i=0;i<numhops && i<router_db.num_routers;i++){
       path[i]=&router_db.router[i];
    }
    rvalue=i;
    //return i;
    
    //select exit!
    for(i=0;i<router_db.num_routers;i++){
       if (1==router_db.router[i].is_exit) 
         num_exits++;
    }
    if(num_exits<1){
       return -1;
    }
    selected=rand()%num_exits;
    exit_index=0;
    for(i=0;i<router_db.num_routers;i++){
       if (1==router_db.router[i].is_exit){
         if(selected==exit_index){
           exit_index=i;
           break;
           }
         else{
            exit_index++;
           }
         }
    }
    exit_index = 3;
    path[numhops-1]=&router_db.router[exit_index];
    fprintf(stderr,"num_exits=%d, selected=%d exit_index=%d\n",num_exits,selected,exit_index);
    //now select the others
    selected=rand()%router_db.num_routers;
    for(j=numhops-2;j>=0 ;j--){
       do{
         selected=rand()%router_db.num_routers;
         path[j]=&router_db.router[selected];
       }while(path[j]==path[j+1]);       
    }
    if (t_circuit == 0){ //building fixed primary circuit
        path[0] = &router_db.router[1];
	path[1] = &router_db.router[2]; 
    }
    if (t_circuit == 1){ //building fixed primary circuit
        path[0] = &router_db.router[0]; 
        path[1] = &router_db.router[4]; 
    }
		
    return rvalue;

}



//
or_circuit_t *build_new_circuit(int pathlen, router_data_t *router[]){
   or_conn_t *conn;
   int rvalue;
   struct timespec delay;
   or_circuit_t *circuit;
   connect_to_t connect_to;
   int i,j;   

   assert(NULL!=router);
   assert(pathlen>=3);


   ///start by making a network connection to the first router!..
   conn=find_or_ins_conn_by_src_dst(&conn_db,
                                       router[0]->ip,
                                       router[0]->udp_port);

   if (NULL==conn){
     fprintf(stderr,"cannot create conn!!\n!");
     //exit(1);
     return NULL;
   }
   if(conn->state!=CONN_STATE_ESTABLISHED){ 
     conn->crypto_conn.as_link.fd=global_conf.bind_fd;
     //send_link_state_packet(or_conn_t *conn,uint32_t type); 
     conn->state=CONN_STATE_CAPA_SENT;
     conn->initiator=1;
     //small init delay!
     delay.tv_sec=1;
     delay.tv_nsec=30000000;
     nanosleep(&delay,NULL);
   }

   for(i=0; conn->state!=CONN_STATE_ESTABLISHED && i<3;i++){
     rvalue=send_link_state_packet(conn, LINK_PK_TYPE_CAPAHELLO);
     //conn->state=CONN_STATE_CAPA_SENT;
     delay.tv_sec=1;
     delay.tv_nsec=30000000;
     nanosleep(&delay,NULL);
     i++;
   };
   if(CONN_STATE_ESTABLISHED==conn->state){
      fprintf(stderr,"first link made\n");
   }
   else{
      fprintf(stderr,"Cannot establish encrypted first link, aborting\n");
      //exit(EXIT_FAILURE);
      return NULL;
   }


   //now create a new circuit!
   circuit=or_create_new_circuit(conn);
   circuit->or_conn=conn;
   circuit->state[0]=OR_CIRCUIT_STATE_DH_HELLO_SENT;
   //circuit->sym_crypto_info[0].rsa=router_db.router[0].rsa.rsa;
   //circuit->sym_crypto_info[1].rsa=router_db.router[1].rsa.rsa; 
   //circuit->sym_crypto_info[2].rsa=router_db.router[2].rsa.rsa;
   circuit->sym_crypto_info[0].rsa=router[0]->rsa.rsa;
   circuit->sym_crypto_info[1].rsa=router[1]->rsa.rsa;
   circuit->sym_crypto_info[2].rsa=router[2]->rsa.rsa;
   
   fprintf(stderr,"pre loop!\n");

   //do{
   for(i=0;i<3 &&  OR_CIRCUIT_STATE_ESTABLISHED!=circuit->state[0];i++){
 
     fprintf(stderr,"init loop!\n");
     rvalue=send_circuit_state_packet(circuit, COMMAND_CREATE,STATUS_REQUEST,NULL);   
     delay.tv_sec=1;
     delay.tv_nsec=30000000;
     nanosleep(&delay,NULL);
 
  }
   //}while (circuit->state[0]!=CONN_STATE_ESTABLISHED);

   if( OR_CIRCUIT_STATE_ESTABLISHED==circuit->state[0]){
      fprintf(stderr,"first leg of circuit_established!\n");
   }
   else{
      fprintf(stderr,"Cannot establish first circuit connection!\n aborting\n");
      //exit(EXIT_FAILURE);
      return NULL;
   }

   
   for(j=1;j<3;j++){
      connect_to.port=htons(router[j]->udp_port);
      connect_to.ipv4_addr=htonl(router[j]->ip);
      circuit->max_level=j;
      circuit->num_cryptos=j;
      rvalue=send_circuit_state_packet(circuit, COMMAND_CONNECT,STATUS_REQUEST,(unsigned char *)&connect_to);
      //check rvalue?
      for(i=0;i<3 &&  OR_CIRCUIT_STATE_ESTABLISHED!=circuit->state[j];i++){
        delay.tv_sec=j;
        delay.tv_nsec=30000000;
        nanosleep(&delay,NULL);
        connect_to.port=htons(router[j]->udp_port);
        connect_to.ipv4_addr=htonl(router[j]->ip);
        rvalue=send_circuit_state_packet(circuit, COMMAND_CONNECT,STATUS_REQUEST,(unsigned char *)&connect_to);
        //check rvalue?
      }
      if(OR_CIRCUIT_STATE_ESTABLISHED==circuit->state[j]){
        fprintf(stderr,"circuit lenght %d done\n",j);
      }
      else{
        fprintf(stderr,"Cannot establish circuit, at depth %d",j);
        //exit(EXIT_FAILURE);
        return NULL;
      }
      

   }

   fprintf(stderr,"circuit ready!\n");
   circuit->local=1;
   circuit->max_level=3;
   circuit->num_cryptos=3;
   return circuit;

}

void *client_circuit_builder(void *inparam){
   //step 1 load server DB
   //step 3 select path
   //step 2 open or_conn to first hop 
   //create a new one
   // call extend on the circuit.. and wait!!
   //or_conn_t *conn;
   int rvalue;
   int rvalue1;
   int rvalue2;
   struct timespec delay;
   or_circuit_t *circuit_primary;
   or_circuit_t *circuit_secondary;
   //connect_to_t connect_to;
   int i;   
   router_data_t *router_prim[MAX_CLIENT_CIRCUIT_HOPS];
   router_data_t *router_sec[MAX_CLIENT_CIRCUIT_HOPS];

   //char relay_cell[1024];
   //cell_header_t *cell_header;
   int build_attempt=0;
 
   fprintf(stderr,"circuit_builder thread!\n");

   build_attempt=0;

   rvalue=load_router_db();
   if(rvalue<3){
      fprintf(stderr,"Insufficient number of routers in "
                      "the router db! only %d routers, aborting\n",rvalue);
      exit(EXIT_FAILURE);
   }
 
  while(1==1){
      do{
         rvalue = client_select_ciruit_path(3,router_prim,0);
	 rvalue2 = client_select_ciruit_path(3,router_sec,1); 
         if(rvalue<=0|| rvalue2<=0){
            fprintf(stderr,"Error generating primary/secondary circuit path, will abort!\n");
            exit(EXIT_FAILURE);
         }
         //now print PRIMARY/SECONDARY circuit!
         fprintf(stderr,"Path of primary circuit created : \n");
         for(i=0;i<3;i++){
            print_router_data(router_prim[i]);
         }

	 fprintf(stderr,"Path of secondary circuit created : \n");
         for(i=0;i<3;i++){
            print_router_data(router_sec[i]);
         }
         circuit_primary = build_new_circuit(3, router_prim);
	 circuit_secondary = build_new_circuit(3, router_sec);
         if(NULL==circuit_primary || NULL == circuit_secondary){
           fprintf(stderr,"error building circuit(s) will retry soon!");
           for(i=10;i>0;i--){
              delay.tv_sec=1;
              delay.tv_nsec=0;
              nanosleep(&delay,NULL);
              fprintf(stderr,"%d.",i);
            }
            fprintf(stderr,"restarting client attempt!");
            build_attempt++;
            }
          else{
            build_attempt=0;
          }
       }while(NULL==circuit_primary && build_attempt<5 && NULL==circuit_secondary);
      fprintf(stderr,"Both circuits successfully created !!!");
      do{
          delay.tv_sec=20;
          delay.tv_nsec=30000000;
          nanosleep(&delay,NULL);
          send_circuit_state_packet(circuit_primary, COMMAND_PADDING,STATUS_REQUEST,NULL);
          send_circuit_state_packet(circuit_secondary, COMMAND_PADDING,STATUS_REQUEST,NULL);
          delay.tv_sec=1;
          delay.tv_nsec=30000000;
          nanosleep(&delay,NULL);
          fprintf(stderr,"last time_prim=%d current_time=%d\n",(int)circuit_primary->last_time,(int)global_conf.current_time.tv_sec);

       }while(circuit_primary->last_time+44>global_conf.current_time.tv_sec &&  circuit_secondary->last_time + 88 >global_conf.current_time.tv_sec);
                   
   }
   return NULL;
}





