/*
**  (C) 2007-2008 Camilo Viecco.  All rights reserved.
**
**  This file is part of Tdor, and is subject to the license terms in the
**  LICENSE file, found in the top level directory of this distribution. If you
**  did not receive the LICENSE file with this file, you may obtain it by contacting
**  the authors listed above. No part of Tdor, including this file,
**  may be copied, modified, propagated, or distributed except according to the
**  terms described in the LICENSE file.
*/

#ifndef CELL_HANDLER_H
#define CELL_HANDLER_H
#include "tor-udp.h"

//this function should be moved to db code!
//or_circuit_t *or_create_new_circuit(or_conn_t *or_conn);

int circuit_send_stream_payload(or_circuit_t *circuit,unsigned char *stream_payload);

int send_circuit_state_packet(or_circuit_t *circuit,uint8_t command,uint8_t status,unsigned char *extra);

int or_cell_handler(or_conn_t *or_conn,unsigned char *in_celli,uint16_t insize);


#endif
