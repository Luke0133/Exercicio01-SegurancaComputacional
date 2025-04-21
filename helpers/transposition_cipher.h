#ifndef TRANSPOSITION_CIPHER_H
#define TRANSPOSITION_CIPHER_H



string enc_transp(string plain_text, string key);         // Encryption function for shift cipher (Enc(M,K))        

string dec_transp(string plain_text, string key);         // Decryption function for shift cipher (Dec(C,K))

string brute_transp_cryptoanalysis(string cipher_text, int key_len, double* ui_time);   // Brute force cryptoanalysis function for shift cipher

string freq_transp_cryptoanalysis(string cipher_text, int key_len, double* ui_time);    // Frequency cryptoanalysis function for shift cipher

int get_transp_key_length(void);

string get_transp_key(int mode, int key_len);                              // Function for getting user input for shift cipher key

string generate_array_transp_key(int* array, int key_len);


#endif