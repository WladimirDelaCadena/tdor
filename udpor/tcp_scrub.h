/* (C) 2008 Camilo Viecco.  All rights reserved.
**
**  This file is part of Tdor, and is subject to the license terms in the
**  LICENSE file, found in the top level directory of this distribution. If you
**  did not receive the LICENSE file with this file, you may obtain it by contacting
**  the authors listed above. No part of Tdor, including this file,
**  may be copied, modified, propagated, or distributed except according to the
**  terms described in the LICENSE file.
*/

#ifndef TCP_SCRUB_H
#define TCP_SCRUB_H

#include "tun_handler.h"

int in_place_tcp_forward_scrub( or_stream_t *in_stream, char *tcp_header);
int in_place_tcp_reverse_scrub(const or_stream_t *out_stream, char *tcp_header);


#endif 

