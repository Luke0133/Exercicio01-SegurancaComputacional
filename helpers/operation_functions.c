#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "operation_functions.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif


int input_int(string query_text){
    while (1) {
        string buffer = input_string(query_text);
        int i = atoi(buffer);
        if (i != 0) {
            free(buffer);
            return i;
        } else {
            int len = strlen(buffer); 
            int isZero = 1; // True
            
            if (buffer[0] != '-' && buffer[0] != '0'){
                isZero = 0;
            }

            int n = 1;
            while (n < len && isZero){
                if (!isdigit(buffer[n])){
                    isZero = 0;  
                }
                n++;
            }

            if (isZero){
                free(buffer);
                return i;
            }
        }
    }
}


string input_string(string query_text){
    while (1) {
        printf("%s", query_text); // Printing query 

        size_t size = 1;                       // Initial allocation size
        string s = malloc(size * sizeof(char)); // Allocating memory for input
        
        // Checking malloc success
        if (s == NULL) {
            printf("Error allocating memory. Program terminated.\n");
            exit(1);
        }

        // Input loop to handle dynamic resizing
        size_t length = 0;
        int character;
        while ((character = getchar()) != '\n' && character != EOF) {
            s[length++] = character;
            
            // Resize buffer if necessary
            if (length >= size) {
                size += 1;
                s = realloc(s, size * sizeof(char));      // Reallocate memory
                if (s == NULL) {
                    free(s);
                    printf("Error reallocating memory. Program terminated.\n");
                    exit(1);
                }
            }
        }
        
        s[length] = '\0';    // Null-terminate the string
        
        // If there's input, return (otherwise, prompt again)
        if (length != 0) {
            return s;
        }
    }
}


void strip_string(string s){
    int i = 0, j = 0;
    while (s[i] != '\0') {
        if (s[i] != ' ' && s[i] != '-' && s[i] != ',' && s[i] != '.' && s[i] != '?' && s[i] != '!' && s[i] != '"' && s[i] != '\'' && s[i] != '(' && s[i] != ')') {
            s[j] = s[i];
            j++;
        }
        i++;
    }
    s[j] = '\0';
}


int mod(int num, int modulo){
    int n = num % modulo;
    return (n >= 0) ? n : (n + modulo);
}

void swap_char(char *x, char *y){
    char temp;
    temp = *x;
    *x = *y;
    *y = temp;
    return;
}

void clrscr() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

double get_time_ms() {
    #ifdef _WIN32
        LARGE_INTEGER freq, counter;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&counter);
        return (double)counter.QuadPart * 1000.0 / freq.QuadPart;
    #else
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (double)(tv.tv_sec) * 1000.0 + (double)(tv.tv_usec) / 1000.0;
    #endif
}