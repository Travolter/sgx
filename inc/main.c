
#include <stdio.h>
#include <SGX/sgx_urts.h>
#include "Enclave/inc_u.h"

#define DEBUG_ENCLAVE 1

int main( int argc, char **argv )
{
	sgx_launch_token_t token = {0};
	sgx_enclave_id_t eid = 0;
	int updated = 0;
	sgx_status_t ret = SGX_SUCCESS;
	unsigned int input, output;

	if ( SGX_SUCCESS != ( ret = sgx_create_enclave( "./Enclave/inc.so", DEBUG_ENCLAVE, &token, &updated, &eid, NULL ) ) )
	{
		printf( "Failed to create enclave\n" );
		return -1;
	}
	
	input = 41;
	//[Warning] The function definition of "inc" has now changed!
	
	if ( SGX_SUCCESS != (ret = inc( eid, &output, input ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "%i −> %i\n", input, output );
	
	if ( SGX_SUCCESS != (ret = sgx_destroy_enclave( eid ) ) )
	{
		printf( "Error destroying enclave (error 0x%x)\n", ret );
		return -3;
	}

}



