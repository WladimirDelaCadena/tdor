/*
**  (C) 2008 Camilo Viecco.  All rights reserved.
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
#include <sys/select.h>
#include "link_conn.h"
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "internal_db.h"

extern global_conf_t global_conf;
extern conn_db_t conn_db;
extern stream_db_t stream_db;

int initialize_conn_db(conn_db_t *db){
   db->head=NULL; 
   pthread_mutex_init(&(db->mutex),NULL);
   return 0;
}
int initialize_circuit_db(circuit_db_t *db){
   db->head=NULL;
   pthread_mutex_init(&(db->mutex),NULL);

   return 0;
}
int initialize_stream_db(stream_db_t *db){
   db->head=NULL;
   return 0;
}

//////////////////////////////////////////////////

or_conn_t *find_or_ins_conn_by_src_dst(conn_db_t *db, uint32_t ip,uint16_t port){
  struct conn_list_element *next;
  int rvalue;
  or_conn_t *r_conn;  

  if (NULL==db){
    return NULL;
  }
  //fprintf(stderr,"[");  
  rvalue=pthread_mutex_lock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex lock, find_or_ins_conn"); exit(1);};
  //fprintf(stderr,"[");

  next=db->head;
  while(next!=NULL){
    if(next->conn.remote_port==port && next->conn.remote_ip==ip){
       //it would be nice to move it to the front!
       r_conn= &((*next).conn);
       goto end;
       //rvalue=pthread_mutex_unlock(&(db->mutex));
       //if(0!=rvalue){perror("error on mutex lock, conn_db"); exit(1);};
       //return &((*next).conn);
    }
    next=next->next;
    //next->next=temp=temp;
  }
  //we got here, then was not found
  fprintf(stderr,"allocating new conn\n");
  next=malloc(sizeof(struct conn_list_element)+sizeof(circuit_db_t));
  if(NULL==next){
     perror("cannot allocate new conn");
     exit(1);
  } 
  memset(next,0x00,sizeof(conn_list_element_t)+sizeof(circuit_db_t));
  next->conn.remote_ip=ip;
  next->conn.remote_port=port;
  next->conn.state=CONN_STATE_NEW;
  next->conn.crypto_conn.as_link.hash_type=CV_HASH_NONE;
  next->conn.crypto_conn.as_link.hash_type=CV_ALG_NONE;
  next->conn.local_iv=rand();
  next->conn.crypto_conn.as_link.fd=global_conf.bind_fd;
  next->conn.rsa=NULL;
  next->conn.circuit_db=((char *)next)+sizeof(conn_list_element_t);
  initialize_circuit_db(next->conn.circuit_db);
  next->conn.last_recv_sec=global_conf.current_time.tv_sec;
  next->next=NULL;
  //set db!
  next->next=db->head;
  db->head=next;

  r_conn= &(next->conn);
end:
  //fprintf(stderr,"done allocating, last_recv=%u,\n",next->conn.last_recv_sec);
  rvalue=pthread_mutex_unlock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex unlock, conn_db"); exit(1);};
  //fprintf(stderr,"]");
  return r_conn;
}


//////////////////////////////////////////////////////////////

or_conn_t *select_random_inactive_conn(conn_db_t *db, uint32_t current_sec){
  or_conn_t *s_conn=NULL;
  struct conn_list_element *db_element;
  int rvalue;
  uint32_t num_cons=0;
  const uint32_t inactive_time=10;
  or_conn_t *conn[128]; //up to 128 conns! 
  uint32_t selected;
  //step 1 make list of inactive conn;
  //go through list again selecting one at random!
  
  //start!
  if (NULL==db){
    return NULL;
  }
  rvalue=pthread_mutex_lock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex lock, select_random_inactive"); exit(1);};  
  //now all other errors -> goto end!
  db_element=db->head;
  while(db_element!=NULL && num_cons<128){

      if(db_element->conn.last_recv_sec+inactive_time<current_sec){
          //add to list
          conn[num_cons]=&(db_element->conn);
          num_cons++;
      }    

      db_element=db_element->next;
  }
  if(num_cons>0){
     selected=rand()%num_cons;
     s_conn=conn[selected];
  }  

end:   
  rvalue=pthread_mutex_unlock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex unlock, select_random_inactive"); exit(1);}

  return s_conn;
}


//////////////////////////////////////////////////////////////

int delete_random_inactive_conn(conn_db_t *db, uint32_t current_sec){
  or_conn_t *s_conn=NULL;
  struct conn_list_element *db_element,*prev;
  int rvalue;
  uint32_t num_cons=0;
  const uint32_t inactive_time=60;
  or_conn_t *conn; //up to 128 conns!
  struct conn_list_element *sconn[128];
  struct conn_list_element *pconn[128];
  
  uint32_t selected;
  //step 1 make list of inactive conn;
  //go through list again selecting one at random!

  //start!
  if (NULL==db){
    return -1;
  }
  rvalue=pthread_mutex_lock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex lock, delete_random_inactive"); exit(1);};
  //now all other errors -> goto end!
  //fprintf(stderr,"deleting inactive conns!\n");
  db_element=db->head;
  prev=db->head;
  while(db_element!=NULL && num_cons<128){

      //if(db_element->conn.last_recv_sec+inactive_time<current_sec){
      if(db_element->conn.last_recv_sec+inactive_time<global_conf.current_time.tv_sec){
#ifdef VERBOSE          
          fprintf(stderr,"conn to del: last_recv=%u, curr=%u\n",db_element->conn.last_recv_sec,global_conf.current_time.tv_sec);
#endif
          //add to list
          //conn[num_cons]=&(db_element->conn);
          sconn[num_cons]=db_element;
          pconn[num_cons]=prev;
          num_cons++;
      }
      prev=db_element;
      db_element=db_element->next;
  }
  if(num_cons>0){
     selected=rand()%num_cons;

     //s_conn=conn[selected];
     if(sconn[selected]==db->head){
        db->head=sconn[selected]->next;
     }
     else{
        pconn[selected]->next=sconn[selected]->next;
     }

     //now delete!
     //cleanup db
     //cleanup_circuit_db(circuit_db_t *db);
      conn=&(sconn[selected]->conn);
     cleanup_circuit_db(conn->circuit_db);

     //and delete! 
     //fprintf(stderr,"deleting old conn!!!!!!!!!!!!!!!!!!!!\n");    
     fprintf(stderr,"about to delete old_conn");
     free(sconn[selected]); 
     fprintf(stderr,"old conn deleted");
  }

end:
  rvalue=pthread_mutex_unlock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex unlock, conn_db"); exit(1);}

  return 0;
}

/////////////////////////////////////////////////////////////////////////////
//this should be in the db code?
// Yes will move it later..
or_circuit_t *or_create_new_circuit(or_conn_t *or_conn){
    or_circuit_t *circuit=NULL;
    uint32_t circ_id;
    if(or_conn==NULL){
       return NULL;
    }
    //lock db?
   

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




/////////////////////////////////////////////////////////////////////////////////////

or_circuit_t *find_or_ins_circ_by_circ_id(circuit_db_t *db,const uint32_t circ_id){
  struct circuit_list_element *next;
  struct circuit_list_element *head;
  int rvalue;
  int mem_size;
  char *allocated;
  if (NULL==db){
    return NULL;
  }
  rvalue=pthread_mutex_lock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex lock, find_or_ins_circ"); exit(1);};

  head=db->head;
  next=db->head;
  while(next!=NULL){
    if(next->circuit.circuit_id==circ_id){
       //it would be nice to move it to the front!

       rvalue=pthread_mutex_unlock(&(db->mutex));
       if(0!=rvalue){perror("error on mutex lock, conn_db"); exit(1);};
       return &((*next).circuit);
    }
    next=next->next;
    //next->next=temp=temp;
  }
  //we got here, then was not found
  if(global_conf.is_client){
    fprintf(stderr,"is client\n");
    mem_size=sizeof(struct circuit_list_element)+MAX_CLIENT_CIRCUIT_HOPS*sizeof(circuit_crypto_conn_t);
  //next=malloc(sizeof(struct circuit_list_element)+MAX_CLIENT_CIRCUIT_HOPS*sizeof(circuit_crypto_conn_t));

  }else{
    mem_size=sizeof(struct circuit_list_element)+sizeof(circuit_crypto_conn_t);
  }

  next=malloc(mem_size);
  if(NULL==next){
     perror("cannot allocate new circuit");
     exit(1);
  }
  fprintf(stderr,"allocated new cicuit at %p\n",&(next->circuit));

  memset(next,0x00,mem_size); 
  allocated=(char*)next;
  next->circuit.circuit_id=circ_id;
  next->circuit.state[0]=OR_CIRCUIT_STATE_NEW;
  next->circuit.sym_crypto_info=(circuit_crypto_conn_t *)(allocated+sizeof(struct circuit_list_element));
  next->circuit.isv_seed=time(NULL) ; ///ok this needs improvement!
  next->circuit.isv_seed|=next->circuit.isv_seed<<32;
  fprintf(stderr,"circ @[%p]sym_crypto @[%p]\n",&(next->circuit),next->circuit.sym_crypto_info);
  fprintf(stderr,"dh [%p]\n",&next->circuit.sym_crypto_info[0].dh);

  //set creation time!
  next->circuit.start_time=global_conf.current_time.tv_sec;


  //insert set db!
  next->next=db->head;
  db->head=next;

  rvalue=pthread_mutex_unlock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex unlock, conn_db"); exit(1);};

  return &next->circuit;


  return NULL;
}

///////////////////////////////////////////////////////////////////////////

or_circuit_t *find_local_circuit(conn_db_t *db){
  struct conn_list_element *next_conn;
  circuit_db_t *circuit_db;
  struct circuit_list_element *next_circ;
  int rvalue;
  or_circuit_t *r_circ=NULL;
  if (NULL==db){
    return NULL;
  }
  rvalue=pthread_mutex_lock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex lock, find_local_circuit"); exit(1);};
  
  next_conn=db->head;

  while(next_conn!=NULL){
    //add another loop!
    circuit_db=(circuit_db_t *)next_conn->conn.circuit_db;
    next_circ=circuit_db->head;
    while(next_circ!=NULL){
       if(next_circ->circuit.local==1){
           r_circ= &((*next_circ).circuit);
           goto end;
       }     
       next_circ=next_circ->next;      
    }
    next_conn=next_conn->next;
    //next->next=temp=temp;
  }
  //we got here, then was not found
end:
  rvalue=pthread_mutex_unlock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex unlock, collector"); exit(1);};

  return r_circ;

}

/*--------------------------------------------

--------------------------------------------*/

int cleanup_circuit_db(circuit_db_t *db){
  struct circuit_list_element *current;
  struct circuit_list_element *to_be_deleted;
  int rvalue=0;
  //or_conn_t *r_conn;
  int i;
  int num_cryptos;

  if (NULL==db){
    return 0;
  }

  rvalue=pthread_mutex_lock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex lock, cleanup_circuit_db"); exit(1);};

  current=db->head;
  while(NULL!=current){
      to_be_deleted=current;
      //clean up stream db if extists
      fprintf(stderr,"about to delete streams\n");
      delete_streams_for_circ(&stream_db,&(to_be_deleted->circuit));
      fprintf(stderr,"after deleted streams\n");

      //now we remove the related if exist!
      // this is a cheap approximation!!
      if(to_be_deleted->circuit.related_circuit!=NULL){
         to_be_deleted->circuit.related_circuit->related_circuit=NULL;
      }
      //now we do a free
      current=current->next;

      num_cryptos=1;
      if(global_conf.is_client){
         num_cryptos=MAX_CLIENT_CIRCUIT_HOPS;
      }
      for(i=0;i<num_cryptos;i++){
         if(NULL!=to_be_deleted->circuit.sym_crypto_info[i].dh){
              DH_free(to_be_deleted->circuit.sym_crypto_info[i].dh);
         }

      }

      free(to_be_deleted);
      rvalue++;
  }
  //and reset the db head!
  db->head=NULL;

  fprintf(stderr,"circuit cleanup, about to unlock db!");
  rvalue=pthread_mutex_unlock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex unlock, cleanup_circuit_db"); exit(1);};
  fprintf(stderr,"circuit_cleanup_done!");

  return rvalue;
}

/*---------------
---------------------*/
int delete_old_circuits(conn_db_t *db, int max_to_delete){

  struct conn_list_element *conn;
  circuit_db_t *circuit_db;
  struct circuit_list_element *circ, *prev,*to_delete;
  int rvalue;
  int num_deleted=0;
  or_circuit_t *r_circ=NULL;
  if (NULL==db){
    return 0;
  }
  rvalue=pthread_mutex_lock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex lock, delete_old_circuits_1"); exit(1);};

  conn=db->head;

  while(conn!=NULL){
    //add another loop!
    circuit_db=(circuit_db_t *)conn->conn.circuit_db;
    rvalue=pthread_mutex_lock(&(circuit_db->mutex));
    if(0!=rvalue){perror("error on mutex lock, delete_old_circuits_2"); exit(1);};

    circ=circuit_db->head;
    prev=circuit_db->head;
    while(circ!=NULL && num_deleted<max_to_delete){
       to_delete=NULL;
       //check for condition
       //urrent->stream.last_time+300<global_conf.current_time.tv_sec
       if(circ->circuit.last_time+120<global_conf.current_time.tv_sec && circ->circuit.start_time+30<global_conf.current_time.tv_sec){
           r_circ= &((*circ).circuit);
           
           // delete_streams_for_circ(stream_db_t *db,const or_circuit_t *circuit)
             
           delete_streams_for_circ(&stream_db, r_circ);
           
           to_delete=circ; 
           num_deleted++;
       }
       //save state
       
       
       if(to_delete!=NULL){
           if(to_delete=circuit_db->head){
              circuit_db->head=circ->next;//now is next!
              circ=circ->next;
              //delete circ
           }
           else{
              prev->next=circ->next;
              circ=circ->next;    
           }
           fprintf(stderr,"deleting old circuit!\n");
           free(to_delete);
       }
       else{
          prev=circ;
          circ=circ->next;
       }
              
    }
    rvalue=pthread_mutex_unlock(&(circuit_db->mutex));
    if(0!=rvalue){perror("error on mutex unlock, delete_circuits_2"); exit(1);};
    if(num_deleted>=max_to_delete){
       goto end;
    }


    conn=conn->next;
    //next->next=temp=temp;
  }
  //we got here, then was not found
end:
  rvalue=pthread_mutex_unlock(&(db->mutex));
  if(0!=rvalue){perror("error on mutex unlock, delete_circuits_1"); exit(1);};

  //return r_circ;

  return num_deleted;
}



/*--------------------------------------------

--------------------------------------------*/


or_stream_t *find_stream_by_ip_port(stream_db_t *db,uint32_t local_ip,uint32_t remote_ip,uint16_t local_port,uint16_t remote_port,uint8_t proto ){
  struct stream_list_element *current;

  if (NULL==db){
    return NULL;
  }
  current=db->head;
  while(current!=NULL){
    if(current->stream.remote_port==remote_port && 
       current->stream.remote_ip==remote_ip &&
       current->stream.local_ip==local_ip &&
       current->stream.local_port==local_port &&
       current->stream.protocol==proto){
       //it would be nice to move to front
       if(NULL!=current->prev){
          //I am not the front so moving makes sense!
          //first remove myself..
          current->prev->next=current->next;
          if(current->next!=NULL){
            current->next->prev=current->prev;
          }
          //now actually put myself in front
          db->head->prev=current;
          current->next=db->head;
          db->head=current;
          current->prev=NULL;
       }

       return &((*current).stream);
    }
    current=current->next;
    //next->next=temp=temp;
  }
  //if we are here was not found!
  return NULL;
}
or_stream_t *find_stream_by_circuit_stream_id(stream_db_t *db, const or_circuit_t *circuit, const uint32_t stream_id){
  struct stream_list_element *current;
  struct stream_list_element *head;
  if (NULL==db){
    return NULL;
  }
  head=db->head;
  current=db->head;
  while(current!=NULL){
    if(circuit   == current->stream.parent_circuit &&
       stream_id == current->stream.stream_id  ){
       //it would be nice to move to front...
       if(NULL!=current->prev){
          //I am not the front so moving makes sense!
          //first remove myself..
          current->prev->next=current->next;
          if(current->next!=NULL){
            current->next->prev=current->prev;
          }
          //now actually put myself in front
          db->head->prev=current;
          current->next=db->head;
          db->head=current;
          current->prev=NULL;          
       }

       return &((*current).stream);
    }
    current=current->next;
    //next->next=temp=temp;
  }
  //if we are here was not found!
  return NULL;


}


or_stream_t *insert_stream_into_db(stream_db_t *db,or_stream_t *in){
  struct stream_list_element *next;
  if (NULL==db){
    return NULL;
  }
  next=malloc(sizeof (stream_list_element_t));
  if(NULL==next) return NULL;
  memcpy(&(next->stream),in,sizeof(or_stream_t));
  //now arrange pointers (4?)
  next->next=db->head;
  next->prev=NULL;
  db->head=next;
  if(next->next!=NULL){
     //there was something, then arrange the previous for it
     next->next->prev=next;
  }

  return &(next->stream);
}



int delete_old_streams(stream_db_t *db,int max_to_delete){
  //we should add  a tail to the db to make searches faster!
  struct stream_list_element *current;
  struct stream_list_element *to_delete;
  int numdeleted=0;
  if (NULL==db){
    return 0;
  }
  current=db->head;
  while(current!=NULL){
     to_delete=NULL;
     //delete on 
     if(current->stream.last_time+300<global_conf.current_time.tv_sec){
         //do delete!
         if(current->prev!=NULL){
            current->prev->next=current->next;
         }
         if(current==db->head){
            //the previous is NULL, we are at the head
            db->head=current->next;
         }
         if(current->next!=NULL){
            current->next->prev=current->prev;
         }     
         to_delete=current;
         numdeleted++;
     }     
     current=current->next;
     assert(db->head!=to_delete);
     //and we can delete now!
     if(NULL!=to_delete){
        free(to_delete);
     }
  }  
  return numdeleted;
}


///
int delete_streams_for_circ(stream_db_t *db,const or_circuit_t *circuit){
  //This assumes that the or_circuit mutex has been adquired by the calling thread!

  struct stream_list_element *current;
  struct stream_list_element *to_delete;
  int numdeleted=0;
  if (NULL==db){
    return 0;
  }
  current=db->head;
  while(current!=NULL){
     to_delete=NULL;
     //delete on
     if(current->stream.parent_circuit==circuit){
         //do delete!
         if(current->prev!=NULL){
            current->prev->next=current->next;
         }
         if(current==db->head){
            //the previous is NULL, we are at the head
            db->head=current->next;
         }
         if(current->next!=NULL){
            current->next->prev=current->prev;
         }
         to_delete=current;
         numdeleted++;
     }
     current=current->next;
     //and we can delete now!
     //assert(db->head!=to_delete);
     if(NULL!=to_delete){
        free(to_delete);
     }
  }
  return numdeleted;
}


