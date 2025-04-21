# Compiler and Flags
CC = gcc
CFLAGS = -Wall -g

# Output files
TARGET1 = main
TARGET2 = transfer_cipher

# Default rule to build both targets
all: $(TARGET1) $(TARGET2)

# Rule to create shift_cipher executable
$(TARGET1): main.c ./helpers/shift_cipher.c ./helpers/shift_cipher.h ./helpers/transposition_cipher.c ./helpers/transposition_cipher.h ./helpers/user_interface.c ./helpers/user_interface.h ./helpers/operation_functions.c ./helpers/operation_functions.h
	$(CC) $(CFLAGS) main.c ./helpers/shift_cipher.c ./helpers/transposition_cipher.c ./helpers/user_interface.c ./helpers/operation_functions.c -o $(TARGET1) -lm

# Rule to create transfer_cipher executable
$(TARGET2): transfer_cipher.c input_functions.c input_functions.h
	$(CC) $(CFLAGS) transfer_cipher.c input_functions.c -o $(TARGET2)

# Clean up executables
clean:
	rm -f $(TARGET1) $(TARGET2)
