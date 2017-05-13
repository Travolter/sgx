#ifndef INC_U_H__
#define INC_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t inc(sgx_enclave_id_t eid, unsigned int* retval, unsigned int input);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
