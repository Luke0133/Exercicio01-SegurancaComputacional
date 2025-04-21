#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include "operation_functions.h"  // NOTE TO SELF: free every string that uses input_string
#include "user_interface.h"
#include "shift_cipher.h"



// Encryption using shift cipher: O(n), where n = strlen(plain_text)
string enc_shift(string plain_text, int key){
    int len = strlen(plain_text);
    string cipher_text = malloc(sizeof(char)*len + 1);
    
    if (!cipher_text) return NULL;
    
    for (int i = 0; i < len; i++){
        // Doesn't shift it character isn't in the alphabet
        if (isalpha(plain_text[i])){
            if (isupper(plain_text[i])){ 
                cipher_text[i] = mod((plain_text[i] - 'A' + key), APLHA_LEN) + 'A';
            } else if (islower(plain_text[i])){
                cipher_text[i] = mod((plain_text[i] - 'a' + key), APLHA_LEN) + 'a';
            }
        } else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[len] = '\0';
    return cipher_text;
}

// Decryption using shift cipher: O(n), where n = strlen(cipher_text)
string dec_shift(string cipher_text, int key){
    int len = strlen(cipher_text);
    string plain_text = malloc(sizeof(char)*len + 1);

    if (!plain_text) return NULL;

    for (int i = 0; i < len; i++){
        // Doesn't shift it character isn't in the alphabet
        if (isalpha(cipher_text[i])){
            if (isupper(cipher_text[i])){ 
                plain_text[i] = mod((cipher_text[i] - 'A' - key), APLHA_LEN) + 'A';
            } else if (islower(cipher_text[i])){
                plain_text[i] = mod((cipher_text[i] - 'a' - key), APLHA_LEN) + 'a';
            }
        } else {
            plain_text[i] = cipher_text[i];
        }
    }
    plain_text[len] = '\0';
    return plain_text;
}

// Brute force cryptoanalysis for shift cipher: O(n), where n = strlen(cipher_text)
int brute_shift_cryptoanalysis(string cipher_text, double* ui_time){
    int len = strlen(cipher_text);
    string found_text = malloc(sizeof(char)*len + 1);
    if (!found_text) return -1;

    double start_time, end_time;
    for (int i = 0; i < APLHA_LEN; i++){
        found_text = dec_shift(cipher_text, i);

        start_time = get_time_ms();
        if (shift_cipher_ui_brute(i,found_text)) {
            end_time = get_time_ms(); 
            *ui_time += end_time - start_time;
            // UI stuff (doesn't impact significantly complexity)
            free(found_text);
            return i;            // The key used
        }
        end_time = get_time_ms(); 
        *ui_time += end_time - start_time;
    }
    
    // Error (NO FOUND TEXT)
    free(found_text);
    return -1;
}

/* Frequency Cryptanalysis

Uses the following frequency table (in https://www.dcc.fc.up.pt/~rvr/naulas/tabelasPT/):
a      b      c      d      e      f      g      h      i      j      k      l      m
13.9   1.0    4.4    5.4    12.2   1.0    1.2    0.8    6.9    0.4    0.1    2.8    4.2

n      o      p      q      r      s      t      u      v      w      x      y      z
5.3    10.8   2.9    0.9    6.9    7.9    4.9    4.0    1.3    0.0    0.3    0.0    0.4

Complexity: O(n), where n = strlen(cipher_text)

*/
static float SINGLE_FREQ[] = {13.9, 1.0, 4.4, 5.4, 12.2, 1.0, 1.2, 0.8, 6.9, 0.4, 0.1, 2.8, 4.2, 5.3, 10.8, 2.9, 0.9, 6.9, 7.9, 4.9, 4.0, 1.3, 0.0, 0.3, 0.0, 0.4};
// Order of most frequent letters:    a  e  o   s   i  r   d  n   t   c  m   u   p   l   v   g  b  f  q   h  j  z   x   k   w   y
static int FREQUENT_SINGLE_INDEX[] = {0, 4, 14, 18, 8, 17, 3, 13, 19, 2, 12, 20, 15, 11, 21, 6, 1, 5, 16, 7, 9, 25, 23, 10, 22, 24};

int freq_shift_cryptoanalysis(string cipher_text, double* ui_time){
    
    float currentSingleFreq[APLHA_LEN] = {0};
    int len = strlen(cipher_text);
    if (len == 0){
        return -1; // Error
    }

    for (int i = 0; i < len; i++){
        // Frequency analysis will only care about ASCII alphabet characters
        if (isalpha(cipher_text[i])){
            if (isupper(cipher_text[i])){ 
                currentSingleFreq[(cipher_text[i] - 'A')]++;
            } else if (islower(cipher_text[i])){
                currentSingleFreq[(cipher_text[i] - 'a')]++;
            }
        }   
    }

    // Finishing table (dividing by len to get frequency in current cipher text)
    int max = 0;  // Stores the index to the 2 highest frequencies 
    for (int i = 0; i < APLHA_LEN; i++){
        currentSingleFreq[i] = currentSingleFreq[i] * 100/len;
        
        // Gets the two highest frequencies indexes
        if (currentSingleFreq[i] > currentSingleFreq[max]){
            max = i;
        } 
    }

    // Checks for most likely frequencies:
    int possible_key;
    string found_text = malloc(sizeof(char)*len + 1);
    if (!found_text) return -1;
    
    int steps = sizeof(FREQUENT_SINGLE_INDEX)/sizeof(FREQUENT_SINGLE_INDEX[0]); 
    double start_time; 
    double end_time; 
    for (int i = 0; i < steps; i++){
        possible_key = mod(max - (FREQUENT_SINGLE_INDEX[i]), APLHA_LEN); 
        found_text = dec_shift(cipher_text, possible_key);
        
        
        start_time = get_time_ms(); 
        if (shift_cipher_ui_freq(possible_key, found_text, max + 'A', currentSingleFreq[max], FREQUENT_SINGLE_INDEX[i] + 'A', SINGLE_FREQ[FREQUENT_SINGLE_INDEX[i]], i + 1)) { 
            end_time = get_time_ms(); 
            *ui_time += end_time - start_time;
            // UI stuff (doesn't impact significantly complexity)
            free(found_text);
            return possible_key;      // The key used
        }
        end_time = get_time_ms(); 
        *ui_time += end_time - start_time;
    }

    // Error (NO FOUND TEXT)
    free(found_text);
    return -1;
}

int get_shift_key(){
    int key;
    while (1){
        key = input_int("Input a Key (between 0 and 25): ");  // Asks for key
        if (key >= 0 && key <= 25){
            return key;
        }
    }
}