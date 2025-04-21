#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "operation_functions.h"  // NOTE TO SELF: free everything that uses these functions
#include "user_interface.h"
#include "shift_cipher.h"
#include "transposition_cipher.h"


void ui_main(int cipher_type){
    srand(time(NULL));    // Setting seed for pseudo-randomic seed generation

    int choice;
    while (1){
        clrscr();
        if (!cipher_type){ // == 0 (SHIFT)
            printf("SHIFT CIPHER:\n");
        } else {  // == 1 (TRANSPOSITION)
            printf("TRANSPOSITION CIPHER (COLUMNAR):\n");
        }
        printf("| 1. Encrypt/Decrypt\n| 2. Make Cryptanalysis\n| 3. Return\n\n");
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1 || choice == 2){
            if (!cipher_type){ // == 0 (SHIFT)
                shift_cipher_ui_mode(choice - 1);
            } else {  // == 1 (TRANSPOSITION)
                transp_cipher_ui_mode(choice - 1);
            }
        } else if (choice == 3){
            return; // 0;
        }
    }
}

void shift_cipher_ui_mode(int mode){
    clrscr();
    if (mode == 0){
        printf("SHIFT CIPHER: Encryption and Decryption mode.\nDescription: Write your plaintext and choose a key (between 0 and 25) for the encryption system.\nThe system will show the ciphertext as well as the decrypted message afterwards.\nNOTE: Resulting plaintexts and ciphertexts won't have any spaces nor punctuation. Non ASCII characters won't be processed (so reults may be underwhelming).\n\n");
    } else {
        printf("SHIFT CIPHER: Cryptanalysis Mode.\nDescription: Write your plaintext. A key will be set pseudo-randomly.\nChoose a method for performing the cryptanalysis afterwards.\nNOTE: Resulting plaintexts and ciphertexts won't have any spaces nor punctuation. Non ASCII characters won't be processed (so reults may be underwhelming).\n\n");
    }
    string plain_text = input_string("Write your plain_text: ");   // User input for plaintext
    strip_string(plain_text);

    int key;
    if (!mode){
        key = get_shift_key(); // User input for key
    } else {
        key = mod(rand(), APLHA_LEN);
        printf("A key has been chosen\n");
        sleep(1);
    }

    double start_time = get_time_ms();
    string cipher_text = enc_shift(plain_text, key);
    double end_time = get_time_ms();

    double time_elapsed = end_time - start_time;


    if (mode == 0){
        clrscr();
        printf("SHIFT CIPHER: Encryption and Decryption Mode.\n\nPlaintext chosen: %s\nChosen Key: %i\n", plain_text, key);
        printf("Resulting Ciphertext: %s\n", cipher_text);
        printf("- Time elapsed during encryption: %f ms\n", time_elapsed);
        free(plain_text);

        start_time = get_time_ms();
        plain_text = dec_shift(cipher_text, key);
        end_time = get_time_ms();
        time_elapsed = end_time - start_time;
        printf("Message decrypted: %s\n", plain_text);      // NOTE: the plain_text string has been modified from dec_shift (it's not copy paste from user input)
        printf("- Time elapsed during decryption: %f ms\n\n", time_elapsed);

        free(plain_text);
        free(cipher_text);
        printf("Press ENTER key to return.\n");
        getchar();
        return;

    }

    //else
    int choice;
    double cryptanalysis_time = 0.0;
    double ui_time = 0.0;
    while(1){
        clrscr();
        printf("SHIFT CIPHER: Cryptanalysis Mode.\nChoose method of cryptanalysis:\n| 1. Brute Force\n| 2. Frequency Analysis\n| 3. Return\n\n");
        printf("Your current ciphertext: %s\n\n", cipher_text);
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1){
            start_time = get_time_ms();
            key = brute_shift_cryptoanalysis(cipher_text, &ui_time);
            end_time = get_time_ms();
            cryptanalysis_time = end_time - start_time - ui_time;
            if (key == -1){
                printf("No key was found\n");
                sleep(1);
                return;
            }

            // Uses found key
            free(plain_text);
            plain_text = dec_shift(cipher_text, key);
            break;
        } else if (choice == 2){
            start_time = get_time_ms();
            key = freq_shift_cryptoanalysis(cipher_text, &ui_time);
            end_time = get_time_ms();
            cryptanalysis_time = end_time - start_time - ui_time;
            if (key == -1){
                printf("No key was found\n");
                sleep(1);
                return;
            }

            // Uses found key
            free(plain_text);
            plain_text = dec_shift(cipher_text, key);
            break;
        } else if (choice == 3){
            free(plain_text);
            free(cipher_text);
            return;
        }
    }

    clrscr();
    printf("SHIFT CIPHER: Cryptanalysis Mode ");
    if (choice == 1){
        printf("(Brute Force)\n");
    } else {
        printf("(Frequency Analysis)\n");
    }
    printf("Resulting Ciphertext: %s\n", cipher_text);
    printf("Key found through cryptanalysis: %i\n", key);
    printf("Message deciphered through cryptanalysis: %s\n", plain_text);
    printf("- Time elapsed during cryptanalysis (Ignoring time spent on UI prompting): %f ms\n\n", cryptanalysis_time);

    free(plain_text);
    free(cipher_text);
    printf("Press ENTER key to return.\n");
    getchar();
    return;

}


int shift_cipher_ui_brute(int possibleKey, string found_text){
    int choice;
    while(1){
        clrscr();
        printf("SHIFT CIPHER: Cryptanalysis Mode (Brute Force)\n");
        printf("Key used: %i\n", possibleKey);
        printf("Possible message: %s\n\n", found_text);
        printf("Choose an option:\n| 1. Continue, this isn't the message I want.\n| 2. Return, this is the message I'm looking for.\n\n");
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1){
            return 0;
        }
        if (choice == 2) {
            return 1;
        }
    }
}

int shift_cipher_ui_freq(int possibleKey, string found_text, char currentCh, float currentFreq, char ch, float chFreq, int iteration){
    int choice;
    while(1){
        clrscr();
        printf("SHIFT CIPHER: Cryptanalysis Mode (Frequency Analysis)\n");
        printf("Iteration %i:\n- Key used: %i.\n- Frequency of letter '%c' in ciphertext: %f.\n- Most likely to be the letter: '%c', with a frequency of: %f.\n", iteration, possibleKey, currentCh, currentFreq, ch, chFreq);
        printf("Possible message: %s\n\n", found_text);
        printf("Choose an option:\n| 1. Continue, this isn't the message I want.\n| 2. Return, this is the message I'm looking for.\n\n");
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1){
            return 0;
        }
        if (choice == 2) {
            return 1;
        }
    }
}


void transp_cipher_ui_mode(int mode){
    clrscr();
    if (mode == 0){
        printf("TRANSPOSITION CIPHER (COLUMNAR): Encryption and Decryption mode.\nDescription: Write your plaintext and choose a key (between 0 and 25) for the encryption system.\nThe system will show the ciphertext as well as the decrypted message afterwards.\nNOTE: Resulting plaintexts and ciphertexts won't have any spaces nor punctuation. Non ASCII characters won't be processed (so reults may be underwhelming).\n\n");
    } else {
        printf("TRANSPOSITION CIPHER (COLUMNAR): Cryptanalysis Mode.\nDescription: Write your plaintext. A key will be set pseudo-randomly.\nChoose a method for performing the cryptanalysis afterwards.\nNOTE: Resulting plaintexts and ciphertexts won't have any spaces nor punctuation. Non ASCII characters won't be processed (so reults may be underwhelming).\n\n");
    }
    string plain_text = input_string("Write your plain_text: ");   // User input for plaintext
    strip_string(plain_text);

    string key = get_transp_key(mode, 0);
    if (!key) return;

    if (mode == 1){
        printf("A key has been chosen\n");
        sleep(1);
    }


    double start_time = get_time_ms();
    string cipher_text = enc_transp(plain_text, key);
    double end_time = get_time_ms();

    double time_elapsed = end_time - start_time;

    if (mode == 0){
        clrscr();
        printf("TRANSPOSITION CIPHER (COLUMNAR): Encryption and Decryption Mode.\n\nPlaintext chosen: %s\nChosen Key: %s\n", plain_text, key);
        printf("Resulting Ciphertext: %s\n", cipher_text);
        printf("- Time elapsed during encryption: %f ms\n", time_elapsed);

        free(plain_text);

        start_time = get_time_ms();
        plain_text = dec_transp(cipher_text, key);
        end_time = get_time_ms();
        time_elapsed = end_time - start_time;
        printf("Message decrypted: %s\n", plain_text);      // NOTE: the plain_text string has been modified from dec_shift (it's not copy paste from user input)
        printf("- Time elapsed during decryption: %f ms\n\n", time_elapsed);


        free(plain_text);
        free(cipher_text);
        free(key);
        printf("Press ENTER key to return.\n");
        getchar();
        return;

    }

    //else
    int choice;
    int key_len = strlen(key);
    string possible_key;
    double cryptanalysis_time = 0.0;
    double ui_time = 0.0;

    while(1){
        clrscr();
        printf("TRANSPOSITION CIPHER (COLUMNAR): Cryptanalysis Mode.\nChoose method of cryptanalysis:\n| 1. Brute Force\n| 2. Frequency Analysis\n| 3. Return\n\n");
        printf("Your current ciphertext: %s\n\n", cipher_text);
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1){

            start_time = get_time_ms();
            possible_key = brute_transp_cryptoanalysis(cipher_text, key_len, &ui_time);
            end_time = get_time_ms();
            cryptanalysis_time = end_time - start_time - ui_time;

            if (!possible_key){
                printf("No key was found\n");
                sleep(1);
                return;
            }

            // Uses found key
            free(plain_text);
            plain_text = dec_transp(cipher_text, key);
            break;
        } else if (choice == 2){

            start_time = get_time_ms();
            possible_key = freq_transp_cryptoanalysis(cipher_text, key_len, &ui_time);
            end_time = get_time_ms();
            cryptanalysis_time = end_time - start_time - ui_time;

            if (!possible_key){
                printf("No key was found\n");
                sleep(1);
                return;
            }

            // Uses found key
            free(plain_text);
            plain_text = dec_transp(cipher_text, possible_key);
            break;
        } else if (choice == 3){
            free(plain_text);
            free(cipher_text);
            free(key);
            return;
        }
    }

    clrscr();
    printf("TRANSPOSITION CIPHER (COLUMNAR): Cryptanalysis Mode ");
    if (choice == 1){
        printf("(Brute Force)\n");
    } else {
        printf("(Frequency Analysis)\n");
    }
    printf("Resulting Ciphertext: %s\n", cipher_text);
    printf("Key found through cryptanalysis: %s\n", possible_key);
    printf("True key (NOT USED FOR DECIPHERING, ONLY SHOWN FOR COMPARISON): %s\n", key);
    printf("Message deciphered through cryptanalysis: %s\n", plain_text);
    printf("- Time elapsed during cryptanalysis (Ignoring time spent on UI prompting): %f ms\n\n", cryptanalysis_time);

    free(plain_text);
    free(cipher_text);
    free(key);
    free(possible_key);
    printf("Press ENTER key to return.\n");
    getchar();
    return;

}

int transp_cipher_ui_brute(string possibleKey, string found_text){
    int choice;
    while(1){
        clrscr();
        printf("TRANSPOSITION CIPHER (COLUMNAR): Cryptanalysis Mode (Brute Force)\n");
        printf("Key used: %s\n", possibleKey);
        printf("Possible message: %s\n\n", found_text);
        printf("Choose an option:\n| 1. Continue, this isn't the message I want.\n| 2. Return, this is the message I'm looking for.\n\n");
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1){
            return 0;
        }
        if (choice == 2) {
            return 1;
        }
    }
}

int transp_cipher_ui_freq(string possibleKey, string found_text, float array[], int keyOrder[]){
    int choice;
    int key_len = strlen(possibleKey);
    while(1){
        clrscr();
        printf("TRANSPOSITION CIPHER (COLUMNAR): Cryptanalysis Mode (Frequency Analysis)\n");
        printf("- Key used: %s.\n- Scores:\n", possibleKey);
        for (int i = 0; i < (key_len - 1); i++){
            printf("  -> %f, for the column pair of indexes %i ('%c' in this key) and %i ('%c' in this key)\n", array[i], keyOrder[i], keyOrder[i] + 'a', keyOrder[i + 1], keyOrder[i+1] + 'a');
        }
        printf("Possible message: %s\n\n", found_text);
        printf("Choose an option:\n| 1. Continue, this isn't the message I want.\n| 2. Return, this is the message I'm looking for.\n\n");
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1){
            return 0;
        }
        if (choice == 2) {
            return 1;
        }
    }
}
