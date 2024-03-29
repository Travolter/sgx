#ifndef INC_T_H__
#define INC_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


unsigned int inc(unsigned int input);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
