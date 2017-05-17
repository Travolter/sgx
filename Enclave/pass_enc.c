#include "pass_enc_t.h"
#include "sgx_trts.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

int get_secret(char* provided_password, char* out_secret);
int set_password(char* provided_password, char* new_password);
int set_secret(char* provided_password, char* new_secret);
int get_number_of_tries_left( void );
int is_acceptible_password( char* password );
//void ocall_print( const char* format, char* value ) ;

char secret[25] = "secret";
char password[25] = "password";
unsigned int number_of_tries_left = 3;

int get_secret(char* provided_password, char* out_secret, size_t len) {

  if (number_of_tries_left > 0 && strcmp(password, provided_password) == 0) {
    number_of_tries_left = 3;
    strncpy(out_secret, secret, sizeof(secret));
    return 1;
  } else {
    number_of_tries_left--;
    strncpy(out_secret, "null", sizeof(secret));
    return 0;
  }
}

int set_password( char* provided_password, char* new_password ) {
  if( !is_acceptible_password( new_password ) ) {
    const char* format = "is not an acceptable password!\n";
    ocall_print( format, new_password );
    return 0;
  }

  if( strcmp(password, provided_password) != 0 )
    return 0;

  strncpy(password,new_password,sizeof(password));
  return 1;
}

int set_secret( char* provided_password, char* new_secret ) {
  if ( strcmp(password, provided_password) == 0 ) {
    strncpy(secret, new_secret, sizeof(secret));
    return 1;
  }
  return 0;
}

int get_number_of_tries_left( void ) {
  return number_of_tries_left;
}


int is_acceptible_password( char* password ) {
  return (strlen(password) <= 25);
}

char* get_correct_password_address( void ) {
  const char* format = "ocall password address %p!\n";
  ocall_print( format, &password );
  return password;
}
int get_secret_attack( char* provided_password, uint64_t out, unsigned int len ) {
  return get_secret( provided_password, (char*) out );
}
