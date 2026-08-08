#ifndef COMPOSITE_KEM_ENCODER_H
#define COMPOSITE_KEM_ENCODER_H

#include "provider.h"

#include <openssl/core.h>

BEGIN_C_DECLS

/* OSSL_OP_ENCODER algorithm list for the composite KEMs. */
const OSSL_ALGORITHM *composite_kem_encoders(void *provctx);

END_C_DECLS

#endif /* COMPOSITE_KEM_ENCODER_H */
