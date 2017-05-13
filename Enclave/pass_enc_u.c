#include "pass_enc_u.h"
#include <errno.h>

typedef struct ms_get_secret_t {
	int ms_retval;
	char* ms_provided_password;
	char* ms_out_secret;
} ms_get_secret_t;

typedef struct ms_set_password_t {
	int ms_retval;
	char* ms_provided_password;
	char* ms_new_password;
} ms_set_password_t;

typedef struct ms_set_secret_t {
	int ms_retval;
	char* ms_provided_password;
	char* ms_new_secret;
} ms_set_secret_t;

typedef struct ms_get_number_of_tries_left_t {
	int ms_retval;
} ms_get_number_of_tries_left_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_pass_enc = {
	0,
	{ NULL },
};
sgx_status_t get_secret(sgx_enclave_id_t eid, int* retval, char* provided_password, char* out_secret)
{
	sgx_status_t status;
	ms_get_secret_t ms;
	ms.ms_provided_password = provided_password;
	ms.ms_out_secret = out_secret;
	status = sgx_ecall(eid, 0, &ocall_table_pass_enc, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t set_password(sgx_enclave_id_t eid, int* retval, char* provided_password, char* new_password)
{
	sgx_status_t status;
	ms_set_password_t ms;
	ms.ms_provided_password = provided_password;
	ms.ms_new_password = new_password;
	status = sgx_ecall(eid, 1, &ocall_table_pass_enc, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t set_secret(sgx_enclave_id_t eid, int* retval, char* provided_password, char* new_secret)
{
	sgx_status_t status;
	ms_set_secret_t ms;
	ms.ms_provided_password = provided_password;
	ms.ms_new_secret = new_secret;
	status = sgx_ecall(eid, 2, &ocall_table_pass_enc, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_number_of_tries_left(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_get_number_of_tries_left_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_pass_enc, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

