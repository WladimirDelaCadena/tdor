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
This sucks, there are not good sock server implementations

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/select.h>
#include <pthread.h>
#include "socks.h"
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BACKLOG 4
#define BUFFER_SIZE 4096
//#define BUFFER_SIZE 2048
#define MAX_FILTER_NETS 20

//
char *default_prohibited_ports="25,138,139,445,6667";
char *default_prohibited_nets="10.0.0.0/8,127.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

//----------------------------
//The filter settings are globals
typedef struct{
   uint32_t net;
   uint8_t mask_size;
}net_filter_t;

uint8_t port_filter[8192];
net_filter_t net_filter[MAX_FILTER_NETS];
uint8_t num_netfilters=0;

//-------------------------
int setup_port_filter(char *in_list){
  //the filter is a comma separated list of diabled ports.
  char disabled_port_list[BUFFER_SIZE];
  char *port_str;
  char *state;
  uint16_t port;
    

  memset(disabled_port_list,0x00,BUFFER_SIZE);
  memset(port_filter,0x00,8192);

  //copy the list into the interna, making sure ours ins null terminated
  strncpy(disabled_port_list,in_list,BUFFER_SIZE-1);   
  
  //do the first,
  fprintf(stdout,"The following ports are disabled:\n");
  port_str=strtok_r(disabled_port_list,",",&state);
  while(port_str!=NULL){
     port=atoi(port_str);
     fprintf(stderr,"%d,",port);
     port_filter[port>>3]=port_filter[port>>3] | (0x1<< (port & 0x7));
     //fprintf(stderr,"port=%d filter[%d]=%d,shift=%d\n",port,port>>3,port_filter[port>>3],port & 0x7); 
     port_str=strtok_r(NULL,",",&state);
  }
  fprintf(stdout,"\n");
  return 0;
}

inline int valid_port(uint16_t port){
   int val;
   val= (port_filter[port>>3]) >> (port & 0x7); 
   //return (val+1)>>1; //negate val
   return (~val) &0x1;
}

/*
int test_filter(){
   int i;
   fprintf(stderr,"port %d, val=%d\n", 80,valid_port(80));
   fprintf(stderr,"port %d, val=%d\n", 25,valid_port(25));
   fprintf(stderr,"port %d, val=%d\n", 34,valid_port(34));
   fprintf(stderr,"port %d, val=%d\n", 6667,valid_port(6667));
   for(i=16;i<32;i++){
      fprintf(stderr,"port %d, val=%d\n", i,valid_port(i));
   }
}
*/
int setup_net_filter(char *in_list){
  //the filter is a comma separated list of diabled ports.
  char disabled_net_list[BUFFER_SIZE];
  char *net_str;
  char *mask_str;
  char *state;
  char *state2;
  uint32_t net;
  uint8_t mask;
  struct in_addr addr;


  memset(disabled_net_list,0x00,BUFFER_SIZE);
  memset(port_filter,0x00,8192);

  //copy the list into the interna, making sure ours ins null terminated
  strncpy(disabled_net_list,in_list,BUFFER_SIZE-1);

  //do the first,
  fprintf(stdout,"The following networks are disabled:\n");
  net_str=strtok_r(disabled_net_list,",",&state);
  if(NULL!=net_str){
     mask_str=strtok_r(net_str,"/",&state2);
     mask_str=strtok_r(NULL,"/",&state2);
  }
  while(net_str!=NULL && mask_str!=NULL &&  num_netfilters<MAX_FILTER_NETS){
     //net=atoi(net_str);
     num_netfilters++;
     mask=atoi(mask_str);
     inet_aton(net_str,&addr);
     net=ntohl(addr.s_addr);
     net_filter[num_netfilters-1].net=net;
     net_filter[num_netfilters-1].mask_size=mask;    
     if(mask>32){
        fprintf(stderr,"bad mask value=%d, aborting\n",mask);
        exit(EXIT_FAILURE);
     }  
     fprintf(stderr,"[%s/%s],",net_str,mask_str);
     net_str=strtok_r(NULL,",",&state);
     if(NULL!=net_str){
        mask_str=strtok_r(net_str,"/",&state2);
        mask_str=strtok_r(NULL,"/",&state2);

     }
  }
  fprintf(stdout,"\n");
  return 0;
}

inline int valid_addr(uint32_t net_addr){
   int val=1;
   int i;
   for(i=0;i<num_netfilters;i++){
      if(ntohl(net_addr)>>(32-net_filter[i].mask_size)==
         net_filter[i].net>>(32-net_filter[i].mask_size)
         )
        return 0;
   }
   //val= (port_filter[port>>3]) >> (port & 0x7);
   //return (val+1)>>1; //negate val
   return val;
}



//-----------------------------------

//a recv that forces to recv the lenght or fail!
ssize_t recv_force(int socket, void *buffer, size_t length, int flags){
   ssize_t rvalue;
   ssize_t recv_bytes=0;
   char *buf=(char *)buffer;

   do{
      rvalue=recv(socket,buf+recv_bytes,length-recv_bytes,flags); 
      if(rvalue<=0){
         recv_bytes=rvalue;
      }   
      else{
         recv_bytes=recv_bytes+rvalue;
      }
   }while(rvalue>0 && recv_bytes<length);

   return recv_bytes; 
}


//returns 0+ on success and fills remote_fd with appropiate value
//does not closes client fd on failure!!!
int handle_socks_conn(int client_fd,int *remote_fd){
   socks4_header_t *socks4_header;
   int num_bytes;
   char buffer[BUFFER_SIZE];
   char *username;
   char *hostname;   
   struct hostent *he;
   struct sockaddr_in remote_addr; 
   int rvalue;

   socks4_header=(socks4_header_t *)buffer;

   num_bytes=recv_force(client_fd,buffer,sizeof(socks4_header_t),0);
   if(num_bytes<=0){
      fprintf(stderr,"recv failed\n");
      return -1;
   }
   //fprintf(stderr,"recv socks_header\n");

   //we only socks 4 and 4a connects
   if(socks4_header->version!=4 ||
      socks4_header->command!=0x1){
      //send fail 
      socks4_header->version=0x00;
      socks4_header->command=0x5b;
      send(client_fd,buffer,sizeof(socks4_header_t),0);
      return -1;
   }
   //fprintf(stderr,"correct version and request!\n");
   //now read until null character!
   username=buffer+sizeof(socks4_header_t)-1;
   do{
      //fprintf(stderr,".");
      username++;
      rvalue=recv(client_fd,username,1,0);
      if(1!=rvalue){
         //error
          return -1;
      }
   }while(*username!=0x00);
   //fprintf(stderr,"got username: %s",buffer+sizeof(socks4_header_t));

   //prepare common stuff 
   memset(&remote_addr,0x0,sizeof(struct sockaddr_in));
   remote_addr.sin_family = AF_INET;    // host byte order 
   remote_addr.sin_port = socks4_header->port;  // short, network byte order 
   //remote_addr.sin_addr = *((struct in_addr *)he->h_addr);
   //memset(their_addr.sin_zero, '\0', sizeof their_addr.sin_zero);

   //check if the port is valid...
   if(!valid_port(ntohs(socks4_header->port)) ){
      //send invalid return..
      socks4_header->version=0x00;
      socks4_header->command=0x5b;
      //fprintf(stderr,"invalid port %d\n",ntohs(socks4_header->port));
      send(client_fd,buffer,sizeof(socks4_header_t),0);
      return -1;
   }


   //if the dest is invalid loop again for the hostname
   if(0== (ntohl(socks4_header->dest) & 0xFFFFFF00) ){
       //fprintf(stderr,"ok so this is sock4a!\n");
       hostname=username;
       do{
         //fprintf(stderr,"*");
         hostname++;
         rvalue=recv(client_fd,hostname,1,0);
         if(1!=rvalue){
            //error
            return -1;
         }
       }while(*hostname!=0x0);
       //now resolve hostname
       //fprintf(stderr,"got hostname %s\n",username+1);
       if ((he=gethostbyname(username+1)) == NULL) {  // get the host info 
          herror("gethostbyname");
          //send failure!
          socks4_header->version=0x00;
          socks4_header->command=0x5b;
          send(client_fd,buffer,sizeof(socks4_header_t),0);
          return -1;
       }
       remote_addr.sin_addr = *((struct in_addr *)he->h_addr);

   }
   else{
       //fprintf(stderr,"got pure ip address, this is socks4! ip=%u\n",ntohl(socks4_header->dest));
       remote_addr.sin_addr.s_addr = socks4_header->dest; //already in network order

   }
   //now we check if the address is valid!
   if(!valid_addr(remote_addr.sin_addr.s_addr) ){
      //send invalid return..
      socks4_header->version=0x00;
      socks4_header->command=0x5b;
      fprintf(stderr,"invalid address %u\n",ntohl(remote_addr.sin_addr.s_addr));
      send(client_fd,buffer,sizeof(socks4_header_t),0);
      return -1;
   }
   
  
   //now make socket 
   if  ((*remote_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
       perror("socket");
       return -1;
   }
   //and connect!
   if (connect(*remote_fd, (struct sockaddr *)&remote_addr,
                                          sizeof remote_addr) == -1) {
        perror("connect");
        fprintf(stderr,"Failed to connect to: %d.%d.%d.%d",
                           ntohl(remote_addr.sin_addr.s_addr)>>24 ,
                           (ntohl(remote_addr.sin_addr.s_addr)>>16) & 0xFF,
                           (ntohl(remote_addr.sin_addr.s_addr)>>8) & 0xFF,
                           ntohl(remote_addr.sin_addr.s_addr) & 0xFF);
        return -1;
   }
   //and send connection accepted!
   socks4_header->version=0x00;
   socks4_header->command=0x5a;
   socks4_header->dest=remote_addr.sin_addr.s_addr;
   rvalue=send(client_fd,buffer,sizeof(socks4_header_t),0);
   if(rvalue!=sizeof(socks4_header_t)){
      //close remote
      close(*remote_fd);
      return -1;
   }

   return 1;
}


void *socks_conn_thread(void *in){
   int client_fd=(int)in;
   int fd[2];
   char buffer[2][BUFFER_SIZE];
   int buffer_fill[2];
   int buffer_sent[2];
   int rvalue;
   fd_set r_set,w_set;
   int i;
   int max_fd;
   struct timeval tv;
   

   fd[0]=client_fd;
   if(0>handle_socks_conn(client_fd,&fd[1])){
       goto end;
   }   
  
   //now prepare
   for(i=0;i<2;i++){
      buffer_fill[i]=0;
      buffer_sent[i]=0;
   }
   //get the max fd, for the select  
   if(fd[0]>fd[1]){
     max_fd=fd[0];
   }else{
     max_fd=fd[1];
   }

   //do a forever loop for processing the data
   while(1==1){
       FD_ZERO(&r_set);
       FD_ZERO(&w_set);
       for(i=0;i<2;i++){
          if(buffer_sent[i]==buffer_fill[i]){
              FD_SET(fd[i],&r_set);
          }else{
              FD_SET(fd[(i+1) % 2 ],&w_set);
          }
       }
       tv.tv_sec = 185;  //after three minutes of inactivity you are out!
       tv.tv_usec = 0;

       //now we do stuff
       do{
         rvalue=select(max_fd+1,&r_set,&w_set,NULL,&tv);
       }while(rvalue==-1 && errno==EINTR);
       if(rvalue==-1){
           perror("select!\n");
           goto end_both;
       }
       if(rvalue==0){
           fprintf(stderr,"timeout exceeded, destroying comm\n");
           goto end_both;
       }
       //we are here means someone fd has data!
       for(i=0;i<2;i++){
          if(buffer_sent[i]==buffer_fill[i]){
              if( FD_ISSET(fd[i],&r_set)){
                  //do something!
                  buffer_fill[i]=recv(fd[i],&buffer[i][0],BUFFER_SIZE,0);
                  buffer_sent[i]=0;
                  if(buffer_fill[i]<=0){
                     goto end_both;
                  }
                  //fprintf(stderr,"after recv i=%d buff_fil=%d buff_sent=%d",i, buffer_fill[i], buffer_sent[i]=0);
              }
          }else{
              if(FD_ISSET(fd[(i+1) %2 ],&w_set)){
                  //fprintf(stderr,"about to send i=%d buff_fil=%d buff_sent=%d",i, buffer_fill[i], buffer_sent[i]=0);

                  rvalue=send(fd[(i+1) %2],
                          &buffer[i][buffer_sent[i]],
                          buffer_fill[i]-buffer_sent[i],
                          0);
                  if(rvalue<=0){
                      goto end_both;
                  }
                  buffer_sent[i]=buffer_sent[i]+rvalue;               
              }
          }

       } 
      
   }

end_both:
   close(fd[1]);
end:
   close(fd[0]);
   return NULL;
}

int usage(){
    fprintf(stdout,"A simple multi-threaded socks server\n");
    fprintf(stdout,"to run:\n socks_server [-D [-l logfilename]] [-p NUM] [-h] [-P LIST] [-N LIST]\n");
    fprintf(stdout,"\t-D\tdeamonize\n");
    fprintf(stdout,"\t-l NAME\tPut log into file NAME\n");
    fprintf(stdout,"\t-p NUM\tMake the server bind to port NUM\n");
    fprintf(stdout,"\t-P LIST\tDisable access to ports in the list\n"
                    "\t\tDefaults to %s.\n",default_prohibited_ports);
    fprintf(stdout,"\t-N LIST\tDisable access to the networks in the list.\n"
                    "\t\tDefaults to %s.\n",default_prohibited_nets);
    fprintf(stdout,"\t-h\tThe help you are seeing\n");
    fprintf(stdout,"\n");
    return 0;
}

void sigint_handler(int sig)
    {
        printf("SIG TERM  Received, exiting!\n");
        exit(1);
    }


void parent_sig_handler(int sig)
    {
        printf("Socks_server: premature failure. Initialization aborted?\n"
               //"Parent sighandler, something  Received,"
                "exiting!\n");
        exit(1);
    }



int main(int argc, char **argv){
   int bind_port=1080;  
   int bind_fd;
   int connected_fd;  
   struct sockaddr_in local_addr;    // my address information
   struct sockaddr_in remote_addr; // connector's address information
   socklen_t sin_size;
   int rvalue;
   int yes=1;
   pthread_t new_thread;
   int deamonize=0;
   char r;
   pid_t pid, sid;
   int log_fd;
   char *log_filename=NULL;
   char *port_list=default_prohibited_ports;
   char *net_list=default_prohibited_nets;

   /* set up the handler */
   if (signal(SIGINT, sigint_handler) == SIG_ERR) {
      perror("signal");
      exit(1);
   }
   if (signal(SIGCHLD, parent_sig_handler) == SIG_ERR) {
       perror("signal");
       exit(EXIT_FAILURE);
   }



   while ((r = getopt(argc, argv, "l:p:P:N:hD")) != -1){
      switch(r){
        case 'l': log_filename=optarg; break;
        case 'D': deamonize=1; break;
        case 'p': bind_port=atoi(optarg); break;
        case 'P': port_list=optarg; break;
        case 'N': net_list=optarg; break;
        case 'h': usage();exit(1);
        }
   }
   //sanity checks go here....

   //now daemonize!
   if(1==deamonize){
      pid=fork();
      if(pid<0){
          fprintf(stderr, "Demonization requested,"
                          " but cant Deamonize(error on fork)."
                          " Aborting execution\n");
          exit(EXIT_FAILURE);
      }
      if(pid>0){
            //this is the parent!
          /*if (signal(SIGCHLD, parent_sig_handler) == SIG_ERR) {
                perror("signal");
                exit(EXIT_FAILURE);
          }*/
          sleep(1);
          //fprintf(stdout, "looks like initialization was a success\n");
          exit(EXIT_SUCCESS);
      
      }
      //this is the child
      sid=setsid();
      if (sid < 0) {
          fprintf(stderr, "Demonization requested,"
                         " but cant Deamonize(error on setsid)."
                         " Aborting execution\n");

          exit(EXIT_FAILURE);
      }
      //maybe redirect output to a log?
      //close(2);
      //close(1);
      if(NULL!=log_filename){
         log_fd=open(log_filename, O_WRONLY|O_CREAT |O_TRUNC, (S_IRUSR | S_IWUSR | S_IRGRP|S_IROTH ) );
         if(0>log_fd){perror("Cannot open deamon log file");exit(EXIT_FAILURE);}
         //redirect stderr and stout and redirect to log file
         dup2(log_fd,2);
         dup2(log_fd,1);
         //close(log_fd);
      }


   }

   //setup filter
   setup_port_filter(port_list);
   //test_filter();
   setup_net_filter(net_list);


   if ((bind_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
       perror("Cannot create socket");
       exit(1);
   }

   if (setsockopt(bind_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
   }
    
   memset(&local_addr,0x00,sizeof( struct sockaddr_in));
   local_addr.sin_family = AF_INET;         // host byte order
   local_addr.sin_port = htons(bind_port);     // short, network byte order
   local_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
   //memset(my_addr.sin_zero, '\0', sizeof my_addr.sin_zero);

   if (bind(bind_fd, (struct sockaddr *)&local_addr, sizeof local_addr) == -1) {
        perror("Cannot bind:");
        exit(1);
   }

   if (listen(bind_fd, BACKLOG) == -1) {
        perror("Cannot listenn");
        exit(1);
   }
 
   //change user here!


   while(1) {  // main accept() loop
      fprintf(stderr,"waiting for connection\n");
      sin_size = sizeof remote_addr;
      if ((connected_fd = accept(bind_fd, (struct sockaddr *)&remote_addr, \
                &sin_size)) == -1) {
         perror("accept");
         continue;
      }
      //fprintf(stderr,"got new connection!\n");

      //next is really ugly passing an int like a pointer!
      rvalue=pthread_create(&new_thread,NULL,socks_conn_thread,(void *)connected_fd); 
      if(0!=rvalue){
         perror("pthread_create!\n");
         exit(1);
      }
      pthread_detach(new_thread);
   }

    return 0;


}

