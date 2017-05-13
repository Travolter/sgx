#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "pass_enc_t.h"

int get_secret(char* provided_password, char* out_secret);
int set_password(char* provided_password, char* new_password);
int set_secret(char* provided_password, char* new_secret);
int get_number_of_tries_left( void );
int is_acceptible_password( char* password );
//void ocall_print( const char* format, char* value ) ;

static char* secret;
static char* password = "init";
static unsigned int number_of_tries_left;

int get_secret(char* provided_password, char* out_secret) {
  number_of_tries_left--;
  
  if (number_of_tries_left > 0 && password == provided_password) {
    number_of_tries_left = 3;
    out_secret = secret;
    return 1;
  } else {
    out_secret = '\0';
    return 0;
  }
}

int set_password( char* provided_password, char* new_password ) {
  if( !is_acceptible_password( new_password ) ) {
    ocall_print( "\"%s\" is not an acceptable password!\n", new_password );
    return 0;
  }

  if( password != provided_password )
    return 0;

  password = provided_password;
}

int set_secret( char* provided_password, char* new_secret ) {
  if ( password == provided_password  ) {
       secret = new_secret ;
       return 1;
  }
  return 0;
}

int get_number_of_tries_left( void ) {
  return number_of_tries_left;
}


int is_acceptible_password( char* password ) {
  return 1;
}

