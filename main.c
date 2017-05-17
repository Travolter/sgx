
#include <stdio.h>
#include <string.h>
#include <SGX/sgx_urts.h>
#include "Enclave/pass_enc_u.h"
#define DEBUG_ENCLAVE 1

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

        static char* old_password = "password";
        static char* new_password = "password2";
        static char* long_password = "passwordpasswordpassword222password2";
        static char* new_secret = "newsecret";

	/*
	 check number of tries left
	 */
	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "Number of tries lef: %i\n ", output );
	/*
	Get secret using intial password (=old_password)
	 */
        char* secret = (char*) malloc(sizeof(char) * 25);
	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, old_password, secret , sizeof(char) * 25 ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		if (output) {
			printf( "used password: %s, ", new_password );
			printf( "Secret is: %s\n ", secret );
		} else {
			printf( "used password: %s, was invalid \n", new_password );
		}

        secret = (char*) malloc(sizeof(char) * 25);
	/*
	 check number of tries left
	 */
	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "Number of tries lef: %i\n ", output );

	/*
	set new_password
	 */
	if ( SGX_SUCCESS != (ret = set_password( eid, &output, old_password, new_password ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "%i, %s −> %s\n", output, old_password, new_password );
	/*
	 check number of tries left
	 */
	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "Number of tries lef: %i\n ", output );

	/*
	Get secret using new password 
	 */
	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, new_password, secret , sizeof(char) * 25) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		if (output) {
			printf( "used password: %s, ", new_password );
			printf( "Secret is: %s\n ", secret );
		} else {
			printf( "used password: %s, was invalid \n", new_password );
		}
	/*
	 check number of tries left
	 */
	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "Number of tries lef: %i\n ", output );


	/*
	set new secret using the new password
	 */
	if ( SGX_SUCCESS != (ret = set_secret( eid, &output, new_password, new_secret ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "%i, Succesfully set secret set to: %s\n", output, new_secret );

	/*
	 check number of tries left
	 */
	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "Number of tries lef: %i\n ", output );
	/*
	Retrieve new secret using the new password
	 */
	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, new_password, secret , sizeof(char) * 25) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		if (output) {
			printf( "used password: %s, ", new_password );
			printf( "Secret is: %s\n ", secret );
		} else {
			printf( "used password: %s, was invalid \n", new_password );
		}
	/*
	try to set long_password
	 */
	if ( SGX_SUCCESS != (ret = set_password( eid, &output, new_password, long_password ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "%i, %s −> %s\n", output, new_password, long_password );

        char* secret = (char*) malloc(sizeof(char) * 25);
	char* passwordaddress;
	/*
	try to retrieve secret using get_corret_password_address
	 */
	if ( SGX_SUCCESS != (ret = get_correct_password_address( eid, &passwordaddress ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		printf( "Password address: %p\n", passwordaddress);

	char* out = (char*) malloc(sizeof(char) * 25);
	unsigned int len;
	if ( SGX_SUCCESS != (ret = get_secret_attack( eid, &output, "wrongpassword", (uint64_t) passwordaddress, sizeof(char) * 25) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		if (output) {
			printf( "used password: %s, ", new_password );
			printf( "Secret is: %s\n ", secret );
		} else {
			printf( "wrong password was given \n" );
		}

	secret = (char*) malloc(sizeof(char) * 25);
	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, "\0", secret , sizeof(char) * 25 ) ) )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
	else
		if (output) {
			printf( "used password: %s, ", new_password );
			printf( "Secret is: %s\n ", secret );
		} else {
			printf( "used password: %s, was invalid \n", new_password );
		}

}
