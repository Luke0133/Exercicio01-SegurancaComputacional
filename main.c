#include <stdio.h>
#include "./helpers/operation_functions.h"  // NOTE TO SELF: free every string that uses input_string
#include "./helpers/user_interface.h"

// Código desenvolvido por Luca Heringer Megiorin - 231003390
// Testado em Windows, pode apresentar comportamento indesejado em Unix (mas não foi testado, então deve funcionar)

int main(){
    int choice;
    while(1){
        clrscr();
        printf("Choose an encryption system:\n| 1. Shift Cipher\n| 2. Transposition Cipher (Columnar)\n| 3. Exit\n\n");
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1 || choice == 2){
            ui_main(choice - 1);
        } else if (choice == 3){
            return 0;
        }
    }
}

