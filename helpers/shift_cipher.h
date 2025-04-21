#ifndef SHIFT_CIPHER_H
#define SHIFT_CIPHER_H



string enc_shift(string plain_text, int key);         // Encryption function for shift cipher (Enc(M,K))        

string dec_shift(string plain_text, int key);         // Decryption function for shift cipher (Dec(C,K))

int brute_shift_cryptoanalysis(string cipher_text, double* ui_time);   // Brute force cryptoanalysis function for shift cipher

int freq_shift_cryptoanalysis(string cipher_text, double* ui_time);    // Frequency cryptoanalysis function for shift cipher
       
int get_shift_key();                                  // Function for getting user input for shift cipher key
 
#endif