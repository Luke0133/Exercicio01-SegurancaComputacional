#ifndef OPERATION_FUNCTIONS_H
#define OPERATION_FUNCTIONS_H

typedef char* string;
#define MAX_LENGTH 2048
#define APLHA_LEN 26  // Alphabet length


int input_int(string arguments);          // Gets input as int

string input_string(string arguments);    // Gets input as char* (string)

void strip_string(string str);           // Removes spaces from string

int mod(int num, int modulo);             // Modulo operation

void swap_char(char *x, char *y);

void clrscr(void);                        // Clear screen

double get_time_ms();

#endif