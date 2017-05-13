#ifndef PASS_ENC_H
#define PASS_ENC_H


int get_secret(char* provided_password, char* out_secret);
int set_password(char* provided_password, char* new_password);
int set_secret(char* provided_password, char* new_secret);
int get_number_of_tries_left( void );
int is_acceptible_password( char* password );
// void ocall_print( const char* format, char* value ) ;

#endif
