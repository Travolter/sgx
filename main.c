
#include <stdio.h>
#include <SGX/sgx_urts.h>
#include "Enclave/pass_enc_u.h"
#define DEBUG_ENCLAVE 1
// OCall implementations
void ocall_print(const char* format, char* value) {
  printf( format, value );
}
int main( int argc, char **argv )
{
	sgx_launch_token_t token = {0};
	sgx_enclave_id_t eid = 0;
	int updated = 0;
	sgx_status_t ret = SGX_SUCCESS;
	unsigned int input, output;

	if ( SGX_SUCCESS != ( ret = sgx_create_enclave( "./Enclave/pass_enc.so", DEBUG_ENCLAVE, &token, &updated, &eid, NULL ) ) )
	{
		printf( "Failed to create enclave\n" );
		return -1;
	}

        static char* provided_password = "init";
        static char* new_password = "init2";
	if ( SGX_SUCCESS != (ret = set_password( eid, &output, provided_password, new_password ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "%s −> %s\n", provided_password, new_password );
	
}
