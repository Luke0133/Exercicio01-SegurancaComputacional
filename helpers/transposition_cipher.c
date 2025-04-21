#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <math.h>
#include "operation_functions.h"  // NOTE TO SELF: free every string that uses input_string
#include "user_interface.h"
#include "transposition_cipher.h"

#include <stdio.h>    // DELETE



// Encryption using shift cipher: O(|K|^2 + N), where: 
// -  N  is roughly the length of the plaintext (+ necessary padding)
// - |K| is the length of the key K
string enc_transp(string plain_text, string key){
    int msg_len = strlen(plain_text);                        // Length of message
    int key_len = strlen(key);                               // Length of key (width of cipher matrix)
    int matrix_height = ceil(msg_len/ (float) key_len);      // Height of cipher matrix
    int len = matrix_height * key_len;                       // Lenght of ciphertext

    string cipher_text = malloc(sizeof(char)*len + 1);
    if (!cipher_text) return NULL;

    
    // Order of indexes for columnar transposition -- O(|K|), where |K| is the length of the key K
    int key_order[key_len];       
    for (int i = 0; i < key_len; i++){
        key_order[i] = i;
    }

    // Simple bubble sorting (to know the order of indexes related to key) --  O(|K|^2), where |K| is the length of the key K
    for (int i = 0; i < key_len; i++){
        for (int j = 0; j < i; j++){
            if((tolower(key[key_order[j]]) - 'a') > (tolower(key[key_order[i]]) - 'a')){
                int temp = key_order[i];
                key_order[i] = key_order[j];
                key_order[j] = temp;
            }
        }
    }
    
    // Building matrix for transposing ciphertext --  O(N), where N is roughly the length of the plaintext (+ necessary padding)
    char cipher_matrix[matrix_height][key_len];  
    int plainIndex;  
    for (int i = 0; i < matrix_height; i++){
        for (int j = 0; j < key_len; j++){
            plainIndex = (key_len * i) + j;
            if (plainIndex >= msg_len){          // Padding
                cipher_matrix[i][j] = '#';
            } else {
                cipher_matrix[i][j] = plain_text[(key_len * i) + j];
            }   
        }
    }

    // Creating ciphertext by concatenating matrixes on the order defined by orderIndex --  O(N), where N is roughly the length of the plaintext (+ necessary padding)
    int index = 0;
    for (int orderIndex = 0; orderIndex < key_len; orderIndex++){
        for (int rowIndex = 0; rowIndex < matrix_height; rowIndex++){ 
            cipher_text[index] = cipher_matrix[rowIndex][key_order[orderIndex]];
            index++;
        }
    }
    
    cipher_text[len] = '\0';
    return cipher_text;
}

// Decryption using shift cipher: O(|K|^2 + N), where: 
// -  N  is the length of the ciphertext
// - |K| is the length of the key K
string dec_transp(string cipher_text, string key){
    int len = strlen(cipher_text);                       // Lenght of ciphertext
    int key_len = strlen(key);                           // Length of key (width of cipher matrix)
    int matrix_height = len / key_len;                   // Height of cipher matrix
    //int msg_len = len - ;                                // Length of message

    //string cipher_text = malloc(sizeof(char)*len + 1);
    //if (!cipher_text) return NULL;

    
    // Order of indexes for columnar transposition -- O(|K|), where |K| is the length of the key K
    int key_order[key_len];       
    for (int i = 0; i < key_len; i++){
        key_order[i] = i;
    }

    // Simple bubble sorting (to know the order of indexes related to key) --  O(|K|^2), where |K| is the length of the key K
    for (int i = 0; i < key_len; i++){
        for (int j = 0; j < i; j++){
            if((tolower(key[key_order[j]]) - 'a') > (tolower(key[key_order[i]]) - 'a')){
                int temp = key_order[i];
                key_order[i] = key_order[j];
                key_order[j] = temp;
            }
        }
    }
    
    // Decrypting ciphertext by reading matrix in the right order matrixes on the order defined by orderIndex --  O(N), where N is roughly the length of the plaintext (+ necessary padding)
    int index = 0;
    int paddingN = 0;
    char cipher_matrix[matrix_height][key_len];  
    for (int orderIndex = 0; orderIndex < key_len; orderIndex++){
        for (int rowIndex = 0; rowIndex < matrix_height; rowIndex++){ 
            cipher_matrix[rowIndex][key_order[orderIndex]] = cipher_text[index];
            if (cipher_text[index] == '#'){
                paddingN++;
            }
            index++;
        }
    }
    
    // Building matrix for transposing ciphertext --  O(N), where N is the length of the ciphertext
    string plain_text = malloc(sizeof(char)*(len - paddingN) + 1); 
    int plainIndex = 0;
    for (int i = 0; i < matrix_height; i++){
        for (int j = 0; j < key_len; j++){
            if (cipher_matrix[i][j] != '#'){//plainIndex < (len - paddingN)) {
                plain_text[plainIndex] = cipher_matrix[i][j];
                plainIndex++;
            }
        }
    }
 
    plain_text[len - paddingN] = '\0';
    return plain_text;
}

// Brute force cryptoanalysis for shift cipher: O(|K|! * (|K|^2 + N))
string brute_transp_cryptoanalysis(string cipher_text, int key_len, double* ui_time){
    double start_time, end_time;
    string possible_key = get_transp_key(2, key_len); // Generates a non-permutated key
    
    string found_text = dec_transp(cipher_text, possible_key);    // Applies non-permutated key

    // First attempt
    start_time = get_time_ms();
    if (transp_cipher_ui_brute(possible_key,found_text)) {
        end_time = get_time_ms(); 
        *ui_time += end_time - start_time;
        // UI stuff (doesn't impact significantly complexity)
        free(found_text);
        return possible_key;            // The key used
    }
    end_time = get_time_ms(); 
    *ui_time += end_time - start_time;

    // Array for keeping track of permutations -- O(|K|) , where |K| is the length of the key K  
    int permuteTracker[key_len];
    for (int i = 0; i < key_len; i++) {
        permuteTracker[i] = 0;
    }

    // Loop that iterates through all possible keys -- O(|K|! * (|K|^2 + N))
    int i = 0;
    while (i < key_len) {
        if (permuteTracker[i] < i) {
            if (i % 2 == 0) {
                swap_char(possible_key, possible_key + i);
            } else {
                swap_char(possible_key + permuteTracker[i], possible_key + i);
            }

            found_text = dec_transp(cipher_text, possible_key);       // O(|K|^2 + N)

            start_time = get_time_ms();
            if (transp_cipher_ui_brute(possible_key,found_text)) {
                end_time = get_time_ms(); 
                *ui_time += end_time - start_time;
                // UI stuff (doesn't impact significantly complexity)
                free(found_text);
                return possible_key;            // The key used
            }
            end_time = get_time_ms(); 
            *ui_time += end_time - start_time;

            permuteTracker[i]++;
            i = 0;
        } else {
            permuteTracker[i] = 0;
            i++;
        }
    }
    
    // Error (NO FOUND TEXT)
    free(found_text);
    free(possible_key);
    return NULL;
}

/* Frequency Cryptanalysis -- O(|K|! * |K|^2 + N)

Uses the frequency table of digraphs (available in https://www.dcc.fc.up.pt/~rvr/naulas/tabelasPT/):
Choose row as first letter and column as second letter

*/


float DIGRAPH_FREQ[26][26] = {
/*A*/{5.13, 2.35, 10.05, 14.8, 4.49, 2.27, 2.14, 0.48, 5.11, 0.57, 0.09, 9.03, 8.08, 11.62, 11.84, 5.84, 1.85, 14.89, 16.41, 5.01, 2.26, 3.04, 0.04, 0.15, 0.08, 0.84},
/*B*/{1.9, 0.02, 0.03, 0.02, 1.9, 0, 0, 0, 1.02, 0.1, 0, 0.83, 0.03, 0, 1.26, 0.02, 0, 1.83, 0.22, 0.07, 0.46, 0.02, 0, 0, 0.01, 0},
/*C*/{12.57, 0.01, 0.45, 0.07, 3.78, 0.01, 0.01, 1.12, 6.09, 0, 0.09, 0.8, 0.02, 0.15, 14, 0.1, 0.02, 1.38, 0.03, 1.62, 1.88, 0, 0, 0, 0, 0},
/*D*/{11.92, 0.02, 0.03, 0.05, 20.33, 0.01, 0.02, 0.02, 4.96, 0.04, 0, 0.02, 0.2, 0.03, 14.45, 0.05, 0.03, 0.5, 0.07, 0.02, 1.13, 0.07, 0.01, 0, 0.02, 0},
/*E*/{6.34, 0.95, 7.25, 5.77, 3.34, 2.17, 2.81, 0.44, 5.31, 0.89, 0.07, 5.97, 10.92, 14.94, 3.24, 3.99, 1.66, 13.33, 20.71, 3.53, 3.28, 2.35, 0.08, 1.52, 0.06, 0.73},
/*F*/{1.56, 0, 0.04, 0.01, 2.03, 0.04, 0, 0, 2.64, 0, 0, 0.21, 0.01, 0.01, 2.21, 0.02, 0, 0.81, 0.01, 0.03, 0.64, 0, 0, 0, 0, 0},
/*G*/{2.6, 0.01, 0.02, 0.03, 1.74, 0.01, 0.01, 0.04, 1.22, 0, 0.01, 0.13, 0.03, 0.21, 2.05, 0.02, 0, 1.56, 0.03, 0.05, 2.52, 0, 0, 0, 0, 0},
/*H*/{2.7, 0, 0.02, 0.02, 1.44, 0.01, 0, 0.02, 0.53, 0, 0, 0.02, 0.03, 0.06, 2.26, 0.01, 0, 0.03, 0.01, 0.04, 0.24, 0, 0, 0, 0, 0},
/*I*/{8.15, 0.67, 6.83, 5.54, 1.16, 0.85, 1.5, 0.02, 0.11, 0.05, 0.05, 2.52, 3.7, 8.22, 4.84, 1.07, 0.18, 4.5, 8.79, 4.9, 0.56, 2.5, 0, 0.45, 0, 1.31},
/*J*/{1.14, 0, 0, 0, 0.56, 0, 0, 0, 0.03, 0, 0, 0, 0, 0, 1.04, 0, 0, 0, 0, 0, 0.75, 0, 0, 0, 0, 0},
/*K*/{0.1, 0, 0.01, 0.01, 0.11, 0.01, 0, 0.02, 0.1, 0, 0.01, 0.02, 0.02, 0.01, 0.09, 0.01, 0, 0.02, 0.03, 0.01, 0.02, 0, 0, 0, 0.01, 0},
/*L*/{4.93, 0.15, 0.52, 1.32, 3.96, 0.18, 0.59, 1.92, 5.22, 0.06, 0.02, 0.31, 0.78, 0.24, 3.43, 0.45, 0.31, 0.1, 0.35, 1.39, 1.16, 0.56, 0, 0, 0.04, 0},
/*M*/{11.35, 1.48, 1.08, 1.29, 8.13, 0.37, 0.2, 0.12, 3.37, 0.16, 0.01, 0.3, 0.66, 0.54, 5.21, 3.49, 0.58, 0.38, 0.86, 0.54, 1.88, 0.27, 0.01, 0, 0.01, 0},
/*N*/{8.65, 0.04, 4.47, 5.27, 2.24, 0.72, 1.05, 1.91, 3.43, 0.14, 0.07, 0.04, 0.05, 0.13, 6.13, 0.06, 0.25, 0.1, 3.05, 13.27, 1.3, 0.64, 0.01, 0, 0.03, 0.06},
/*O*/{5.41, 2.08, 5.37, 9.58, 6.29, 1.89, 1.73, 0.47, 2.79, 0.83, 0.06, 3.66, 7.79, 10.14, 2.04, 6.3, 1.84, 11.85, 18.26, 2.55, 4.06, 2.24, 0.08, 0.25, 0.03, 0.16},
/*P*/{6.74, 0, 0.17, 0.05, 5.23, 0.02, 0.01, 0.04, 0.93, 0.01, 0, 0.86, 0.02, 0.03, 7.46, 0.1, 0.02, 6.02, 0.26, 0.21, 0.93, 0.01, 0, 0, 0, 0},
/*Q*/{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9.38, 0, 0, 0, 0, 0},
/*R*/{17.43, 0.28, 2.34, 2.41, 14.16, 0.31, 0.92, 0.07, 8.06, 0.1, 0.05, 0.41, 1.88, 1.61, 8.11, 0.85, 0.81, 1.84, 1.31, 3.73, 1.53, 0.66, 0.01, 0, 0.05, 0.02},
/*S*/{9.19, 0.66, 4.18, 6.33, 13.47, 1.19, 0.39, 0.57, 4.72, 0.38, 0.06, 0.65, 2.37, 1.82, 5.91, 5.2, 1.47, 1.05, 6.33, 9.8, 2.58, 0.63, 0.02, 0, 0.01, 0.03},
/*T*/{11.46, 0.01, 0.09, 0.03, 12.72, 0.01, 0.01, 0.15, 6.17, 0.01, 0, 0.07, 0.06, 0.04, 9.33, 0.07, 0.01, 5.83, 0.11, 0.12, 2.94, 0.03, 0.01, 0, 0.02, 0.02},
/*U*/{3.98, 1.01, 1.05, 1.22, 8.55, 0.14, 0.87, 0.03, 2.55, 0.15, 0.02, 2.15, 5.54, 3.2, 0.51, 0.96, 0.18, 2.72, 2.07, 2.17, 0.15, 0.26, 0, 0.07, 0, 0.24},
/*V*/{3.36, 0, 0.01, 0.01, 4.75, 0, 0, 0, 3.19, 0, 0, 0.01, 0.01, 0, 1.75, 0.01, 0, 0.17, 0.01, 0, 0.07, 0, 0, 0, 0, 0},
/*W*/{0.11, 0, 0, 0, 0.05, 0, 0, 0.01, 0.06, 0, 0, 0, 0, 0.01, 0.04, 0, 0, 0, 0.01, 0, 0, 0, 0, 0, 0, 0},
/*X*/{0.45, 0, 0.13, 0.01, 0.32, 0, 0, 0, 0.58, 0, 0, 0, 0.01, 0, 0.2, 0.42, 0, 0, 0.01, 0.24, 0.03, 0.01, 0, 0.01, 0, 0},
/*Y*/{0.06, 0.01, 0.02, 0.02, 0.05, 0.01, 0, 0, 0.01, 0, 0, 0.02, 0.02, 0.02, 0.05, 0.01, 0, 0.01, 0.03, 0.01, 0.01, 0, 0.01, 0, 0, 0},
/*Z*/{1.2, 0.01, 0.05, 0.15, 0.86, 0.02, 0, 0.01, 0.29, 0.01, 0, 0.01, 0.08, 0.05, 0.33, 0.07, 0.08, 0.02, 0.05, 0.02, 0.06, 0.01, 0, 0, 0, 0.02}
};

string freq_transp_cryptoanalysis(string cipher_text, int key_len, double* ui_time){
    double start_time, end_time;
    int len = strlen(cipher_text);                       // Lenght of ciphertext
    int matrix_height = len / key_len;                   // Height of cipher matrix

    // Building a (currently unordered) matrix with given ciphertext --  O(N), where N is the length of the ciphertext
    int paddingN = 0;
    int index = 0;
    char cipher_matrix[matrix_height][key_len];  
    for (int rowIndex = 0; rowIndex < matrix_height; rowIndex++){
        for (int columnIndex = 0; columnIndex < key_len; columnIndex++){ 
            cipher_matrix[rowIndex][columnIndex] = cipher_text[index];
            index++;
            if (cipher_text[index] == '#'){
                paddingN++;
            }
        }
    }

    // Creating column pairs scores matrix -- O(|K| × (|K| - 1)) => O(|K|^2)
    digraphPair digraphScores[key_len][key_len - 1];
    for (int i = 0; i < key_len; i++) {
        for (int j = 0; j < (key_len - 1); j++) {
            digraphScores[i][j].fstColumn = -1;
            digraphScores[i][j].sndColumn = -1;
            digraphScores[i][j].score = 0;
        }
    }

    // Building scores for column pairs based on digraphs frequency -- O(|K| * (|K| - 1) × N/|K|) => O(|K| × N)
    int sndIndex, firstLetter, secondLetter;
    for (int i = 0; i < key_len; i++) {                                       // Repeats |K| times
        sndIndex = 0;
        for (int j = 0; j < (key_len - 1); j++) {                             // Repeats |K - 1| times
            if (i == sndIndex){
                sndIndex++;
            }
            for (int rowIndex = 0; rowIndex < matrix_height; rowIndex++){     // Repeats matrix_height = N/|K| times 
                digraphScores[i][j].fstColumn = i;
                digraphScores[i][j].sndColumn = sndIndex;
                firstLetter = cipher_matrix[rowIndex][i];
                secondLetter = cipher_matrix[rowIndex][sndIndex];
                
                if (firstLetter != '#' && secondLetter != '#'){
                    digraphScores[i][j].score += DIGRAPH_FREQ[(tolower(firstLetter) - 'a')][(tolower(secondLetter) - 'a')];
                } 
            }
            sndIndex++;
        }        
    }

    // Bubble sorting each column scores, so that highest scores pairs are chosen first -- O(|K|^3)
    for (int digraphColumn = 0; digraphColumn < key_len; digraphColumn++){              // Repeats |K| times
        // Bubble sort for a single column -- O(|K-1|^2) => O(|K|^2)
        for (int i = 0; i < (key_len - 1); i++){                                        // Repeats |K - 1| times        
            for (int j = 0; j < i; j++){                                                // Repeats roughly |K - 1| times
                if(digraphScores[digraphColumn][j].score < digraphScores[digraphColumn][i].score){     
                    digraphPair temp = digraphScores[digraphColumn][i];
                    digraphScores[digraphColumn][i] = digraphScores[digraphColumn][j];
                    digraphScores[digraphColumn][j] = temp;
                }
            }
        }
    }
    
    // Creating a priority list for which column should be the starting one (based on scores) -- O(|K|)
    int columnPriority[key_len];
    for (int i = 0; i < key_len; i++){
        columnPriority[i] = digraphScores[i][0].fstColumn;
    } 

    // Bubble sorts the priority list based on scores -- O(|K|^2)
    for (int i = 0; i < key_len; i++){
        for (int j = 0; j < i; j++){
            if(digraphScores[columnPriority[j]][0].score < digraphScores[columnPriority[i]][0].score){
                int temp = columnPriority[i];
                columnPriority[i] = columnPriority[j];
                columnPriority[j] = temp;
            }
        }
    }


    int keyOrder[key_len];          // Stores the order of the columns, which translates to a possible key
    int currentColumns[key_len];    // Stores which of the (key_len - 1) digraph combinations each column is using
    int used[key_len];              // 0 if column combination wasn't used yet
    float currentScores[key_len - 1];

    // Setting up the previously mentioned arrays -- O(|K|)
    for (int i = 0; i < key_len; i++){
        keyOrder[i] = -1;
        currentColumns[i] = 0;
        used[i] = 0;
        if (i < key_len - 1){
            currentScores[i] = 0;
        }
    } 

    
    string possible_key;
    string found_text;
    int startingColumn;

    // Loops through all possible key combinations, based on the highest scores -- O(|K|! * |K|^2 + N), since:
    // 1 - Tests through all possible combinations (worst case) -- O(|K|!)
    // 2 - For each combination, tries to decrypt using possible key -- O(|K|^2 + N)
    for (int scIndex = 0; scIndex < key_len; scIndex++) {         
        startingColumn = columnPriority[scIndex];
        keyOrder[0] = startingColumn;
        used[startingColumn] = 1;
        
        int i = 1; // Index for building keyOrder
        while (i >= 1) {                                        
            if (i == key_len) {   // If we have a full permutation, use keyOrder to decrypt ciphertext=
                possible_key = generate_array_transp_key(keyOrder, key_len); // Generates key from keyOrder array -- O(|K|)
                found_text = dec_transp(cipher_text, possible_key);          // Decrypts using possible key -- O(|K|^2 + N)
       
                start_time = get_time_ms();
                if (transp_cipher_ui_freq(possible_key,found_text,currentScores,keyOrder)) {
                    end_time = get_time_ms(); 
                    *ui_time += end_time - start_time;
                    // UI stuff (doesn't impact significantly complexity)
                    free(found_text);
                    return possible_key;            // The key used
                }
                end_time = get_time_ms(); 
                *ui_time += end_time - start_time;

                // If possible_key wasn't accepted, backtrack to find next available option
                i--;
                used[keyOrder[i]] = 0;   // Resets previous column (frees from it being used)
                currentColumns[i]++;     // Sets to try the next highest score pair for the previous column
                continue;
            }

            int leftCol = keyOrder[i - 1];
            int foundNext = 0;

            while (currentColumns[i] < key_len - 1) {      // Loops until it finds a valid pair or exceeds key_len - 1   -- O(|K| - 1 ) => O(|K|)
                int candidateCol = digraphScores[leftCol][currentColumns[i]].sndColumn;
                if (!used[candidateCol]) {                 // If column isn't already in keyOrder
                    keyOrder[i] = candidateCol;
                    used[candidateCol] = 1;
                    currentScores[i - 1] = digraphScores[leftCol][currentColumns[i]].score;
                    if (i < (key_len - 1)){
                        currentColumns[i + 1] = 0;             // Resets the next column's pair index, so that all combinations are tried
                    }
                    foundNext = 1;
                    i++;
                    break;
                }

                currentColumns[i]++;   // If pair isn't available, try next pairing
            }
            
            
            if (!foundNext) {       // If no pair was found, it means there are no more possible combinations with this order, so backtrack
                if (i > 0) {  // If i hasn't reached the starting column, continue backtracking                
                    i--;
                    used[keyOrder[i]] = 0;   // Resets previous column (frees from it being used)
                    currentColumns[i]++;     // Sets to try the next highest score pair for the previous column

                } else {   // Otherwise, change the starting column by breaking from this loop (every combination was already explored)
                    break;
                }
            }
        }
        
        // Reset for next startingColumn -- O(|K|)
        for (int j = 0; j < key_len; j++) {
            used[j] = 0;                // Sets every column to unused
            currentColumns[j] = 0;      // Resets every combination, to that algorithm gets the highest score pair
            keyOrder[j] = -1;           // Sets keyOrder to an invalid state
        }
    }

    // Error (NO FOUND TEXT)
    free(found_text);
    free(possible_key);
    return NULL;
}

int get_transp_key_length(void){
    while (1){
        int key = input_int("How long is your key? Input a number between 2 and 26: ");  // Asks for key length
        if (key > 0 && key <= 26){
            return key;
        }
    }
}

string get_transp_key(int mode, int key_len){
    if (!(key_len > 1) || !(key_len <= 26)){   // If key_len == 0, for instance, prompt for length
        while (1){
            key_len = input_int("How long is your key? Input a number between 2 and 26: ");  // Asks for key length
            if (key_len > 1 && key_len <= 26){
                break;
            }
        }
    }

    string key = malloc(sizeof(char)*key_len + 1);
    if (!key) return NULL;

    int valid;
    while (1){
        valid = 1;
        if (!mode){    // Enc/Dec mode asks user for key
            key = input_string("Input key of your chosen length (No repeating characters, ASCII only): ");
            
            if (strlen(key) != key_len){
                valid = 0;
            }

            if (valid){
                for (int i =0; i < key_len; i++){
                    if (!isalpha(key[i])){
                        valid = 0;
                        break;
                    }
                    key[i] = tolower(key[i]);
                }
    
                for (int i =0; i < key_len; i++){
                    for (int j =0; j < i; j++){
                        if ((i != j) && (key[i] == key[j])){
                            valid = 0;
                            break;
                        }
                    }
                    if (!valid){
                        break;
                    }
                }
            }
            
            if (valid){
                return key;
            }
        } else if (mode == 2){
            for (int i =0; i < key_len; i++){
                key[i] = i + 'a';
            }
            key[key_len] = '\0';
            return key;
        } else {
            int i = 0;
            int j = 0;
            while (i < key_len){
                char ch = mod(rand(), APLHA_LEN) + 'a';

                for (j = 0; j < i; j++)
                {     
                    if(key[j]== ch){
                        break;
                    }
                }
                if(j==i){
                    // If letter is unique
                    key[i]= ch;
                    i++;
                }     
            }
            
            key[key_len] = '\0';
            
            return key;
        }
    }

    // If error
    return NULL;
}


string generate_array_transp_key(int* array, int key_len){
    string key = malloc(sizeof(char)*key_len + 1);
    if (!key) return NULL;

    for (int i = 0; i < key_len; i++){
        key[i] = 'a' + array[i];
    }

    key[key_len] = '\0';
    return key;
}