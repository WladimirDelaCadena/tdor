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

#ifndef INTERNAL_DB_H
#define INTERNAL_DB_H
#include "tor-udp.h"
#include <pthread.h>


struct conn_list_element{
   struct conn_list_element *next;
   or_conn_t conn;
   or_conn_t conn_sec;
};

typedef struct conn_list_element conn_list_element_t; 

typedef struct {
   struct conn_list_element *head;
   pthread_mutex_t mutex;
}conn_db_t;
//typedef struct conn_db_st conn_db_t;

//--------------------------------------------
struct circuit_list_element{
   struct circuit_list_element *next;
   or_circuit_t circuit;
};

typedef struct circuit_list_element circuit_list_element_t;

typedef struct {
   struct circuit_list_element *head;
   pthread_mutex_t mutex;
}circuit_db_t;

//------------------------------------------


struct stream_list_element{
   struct stream_list_element *prev;
   struct stream_list_element *next;
   or_stream_t stream;
};

typedef struct stream_list_element stream_list_element_t;

typedef struct {
   struct stream_list_element *head;
}stream_db_t;

//---------------------
//operations
// in udp packet-> conn
// conn,circ_id ->circ
// circ,stream_id -> stream
// in tun packet-> stream
// find a local circuit,

int initialize_conn_db(conn_db_t *db);
int initialize_circuit_db(circuit_db_t *db);
int initialize_stream_db(stream_db_t *db);

or_conn_t *find_or_ins_conn_by_src_dst(conn_db_t *db, uint32_t ip,uint16_t port);
or_conn_t *select_random_inactive_conn(conn_db_t *db, uint32_t current_sec);
int delete_random_inactive_conn(conn_db_t *db, uint32_t current_sec);
//this function should be moved to db code!
or_circuit_t *or_create_new_circuit(or_conn_t *or_conn);

or_circuit_t *find_or_ins_circ_by_circ_id(circuit_db_t *db,const uint32_t circ_id);
int cleanup_circuit_db(circuit_db_t *db);
or_circuit_t *find_local_circuit(conn_db_t *db);
int delete_old_circuits(conn_db_t *db, int max_to_delete);

or_stream_t *find_stream_by_ip_port(stream_db_t *db,uint32_t local_ip,uint32_t remote_ip,uint16_t local_port,uint16_t remote_port,uint8_t proto );
or_stream_t *find_stream_by_circuit_stream_id(stream_db_t *db,const or_circuit_t *circuit, const uint32_t stream_id);
or_stream_t *insert_stream_into_db(stream_db_t *db, or_stream_t *in);
int delete_old_streams(stream_db_t *db,int max_to_delete);
int delete_streams_for_circ(stream_db_t *db,const or_circuit_t *circuit);
#endif



