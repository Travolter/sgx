#include <string.h>
#include <stdint.h>

static char* secret;
static char* password = "init";
static unsigned int number_of_tries_left;

int get_secret(char* provided_password, char* out_secret) {
  number_of_tries_left--;
  
  if (number_of_tries_left > 0 && password == provided_password) {
    number_of_tries_left = 3;
    out_secret = secret;
    return true
  } else {
    out_secret = '\0';
    return false;
  }
}

int set_password( char* provided_password, char* new_password ) {
  if( !is_acceptible_password( new_password ) ) {
    ocall_print( "\"%s\" is not an acceptable password!\n", new_password );
    return false;
  }

  if( password != provided_password )
    return false;

  password = provided_password
}

int set_secret( char* provided_password, char* new_secret ) {
  if is_acceptible_password( provided_password ) {
       secret = new_secret 
  }
}

int get_number_of_tries_left( void ) {
  return number_of_tries_left
}


