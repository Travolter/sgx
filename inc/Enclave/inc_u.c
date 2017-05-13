#include "inc_u.h"
#include <errno.h>

typedef struct ms_inc_t {
	unsigned int ms_retval;
	unsigned int ms_input;
} ms_inc_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_inc = {
	0,
	{ NULL },
};
sgx_status_t inc(sgx_enclave_id_t eid, unsigned int* retval, unsigned int input)
{
	sgx_status_t status;
	ms_inc_t ms;
	ms.ms_input = input;
	status = sgx_ecall(eid, 0, &ocall_table_inc, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

