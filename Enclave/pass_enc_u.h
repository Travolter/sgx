#ifndef PASS_ENC_U_H__
#define PASS_ENC_U_H__

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

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* format_string, char* value));

sgx_status_t get_secret(sgx_enclave_id_t eid, int* retval, char* provided_password, char* out_secret);
sgx_status_t set_password(sgx_enclave_id_t eid, int* retval, char* provided_password, char* new_password);
sgx_status_t set_secret(sgx_enclave_id_t eid, int* retval, char* provided_password, char* new_secret);
sgx_status_t get_number_of_tries_left(sgx_enclave_id_t eid, int* retval);
sgx_status_t get_correct_password_address(sgx_enclave_id_t eid, char** retval);
sgx_status_t get_secret_attack(sgx_enclave_id_t eid, int* retval, char* provided_password, uint64_t out, unsigned int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
