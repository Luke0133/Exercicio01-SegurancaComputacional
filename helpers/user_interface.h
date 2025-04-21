#ifndef USER_INTERFACE_H
#define USER_INTERFACE_H


typedef struct {
      int fstColumn;
      int sndColumn;
      float score;
} digraphPair;

void ui_main(int cipher_type);           // Main user interface for shift cipher

void shift_cipher_ui_mode(int mode);        // Encryption/Cryptanalysis mode interface for shift cipher

int shift_cipher_ui_brute(int possibleKey, string found_text);

int shift_cipher_ui_freq(int possibleKey, string found_text, char currentCh, float currentFreq, char ch, float chFreq, int iteration);

void transp_cipher_ui_mode(int mode);        // Encryption/Cryptanalysis mode interface for transposition cipher

int transp_cipher_ui_brute(string possibleKey, string found_text);

int transp_cipher_ui_freq(string possibleKey, string found_text, float array[], int keyOrder[]);
#endif