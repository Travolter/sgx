#ifndef PASS_ENC_H
#define PASS_ENC_H


int get_secret(char* provided_password, char* out_secret, size_t len);
int set_password(char* provided_password, char* new_password);
int set_secret(char* provided_password, char* new_secret);
int get_number_of_tries_left( void );
int is_acceptible_password( char* password );
char* get_correct_password_address( void );
int get_secret_attack( [user_check] char* provided_password, uint64_t out, unsigned int len);
// void ocall_print( const char* format, char* value ) ;

#endif
