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

#ifndef LOCAL_CIRCUIT_BUILDER_H
#define LOCAL_CIRCUIT_BUILDER_H

#include "tor-udp.h"
#include "cell_handler.h"
//#include "circuit_crypto.h"
#include "internal_db.h"
#include "link_conn.h"

#define MAX_ROUTERS 128
#define ROUTER_LINE_MAX 1024

typedef struct{
   router_data_t router[MAX_ROUTERS];
   uint16_t num_routers;
}router_db_t;

void *client_circuit_builder(void *);


#endif
