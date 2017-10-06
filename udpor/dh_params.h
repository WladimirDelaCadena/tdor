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

#ifndef DH_PARAMS_H
#define DH_PARAMS_H

#ifndef HEADER_DH_H
#include <openssl/dh.h>
#endif
DH *get_dh512();
DH *get_dh1024();

#endif
