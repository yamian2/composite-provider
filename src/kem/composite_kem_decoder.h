#ifndef COMPOSITE_KEM_DECODER_H
#define COMPOSITE_KEM_DECODER_H

#include "provider.h"

#include <openssl/core.h>

BEGIN_C_DECLS

/* OSSL_OP_DECODER algorithm list for the composite KEMs. */
const OSSL_ALGORITHM *composite_kem_decoders(void *provctx);

END_C_DECLS

#endif /* COMPOSITE_KEM_DECODER_H */
