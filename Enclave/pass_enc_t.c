#include "pass_enc_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_get_secret(void* pms)
{
	ms_get_secret_t* ms = SGX_CAST(ms_get_secret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_provided_password = ms->ms_provided_password;
	char* _tmp_out_secret = ms->ms_out_secret;

	CHECK_REF_POINTER(pms, sizeof(ms_get_secret_t));

	ms->ms_retval = get_secret(_tmp_provided_password, _tmp_out_secret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_set_password(void* pms)
{
	ms_set_password_t* ms = SGX_CAST(ms_set_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_provided_password = ms->ms_provided_password;
	char* _tmp_new_password = ms->ms_new_password;

	CHECK_REF_POINTER(pms, sizeof(ms_set_password_t));

	ms->ms_retval = set_password(_tmp_provided_password, _tmp_new_password);


	return status;
}

static sgx_status_t SGX_CDECL sgx_set_secret(void* pms)
{
	ms_set_secret_t* ms = SGX_CAST(ms_set_secret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_provided_password = ms->ms_provided_password;
	char* _tmp_new_secret = ms->ms_new_secret;

	CHECK_REF_POINTER(pms, sizeof(ms_set_secret_t));

	ms->ms_retval = set_secret(_tmp_provided_password, _tmp_new_secret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_number_of_tries_left(void* pms)
{
	ms_get_number_of_tries_left_t* ms = SGX_CAST(ms_get_number_of_tries_left_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_get_number_of_tries_left_t));

	ms->ms_retval = get_number_of_tries_left();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_get_secret, 0},
		{(void*)(uintptr_t)sgx_set_password, 0},
		{(void*)(uintptr_t)sgx_set_secret, 0},
		{(void*)(uintptr_t)sgx_get_number_of_tries_left, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};

