#ifndef PASS_ENC_T_H__
#define PASS_ENC_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int get_secret(char* provided_password, char* out_secret);
int set_password(char* provided_password, char* new_password);
int set_secret(char* provided_password, char* new_secret);
int get_number_of_tries_left();

sgx_status_t SGX_CDECL ocall_print(const char* format_string, char* value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
