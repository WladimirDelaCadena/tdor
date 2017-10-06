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
This file defines abstract interfaces for communication with the directory servers
The communication is done via the global conf struct or via explicit pointers!
*/


#ifndef DS_COMM_H
#define DS_COMM_H

#include <curl/curl.h>
#include <curl/types.h>


#define DS_COMM_VERSION 1

int init_ds_comm();
int upload_server_descriptor();
int dowload_server_lists();

void *directory_server_status_updater(void *);


#endif
