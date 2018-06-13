#include "debug.h"

void print_memory(unsigned char* memory, size_t size) {
    #ifdef __DEBUG
    for (int i = 0; i < size; i++) {
        printf("%2x", memory[i]);
    }
    #endif
}

void nothing(char* arg, ...) {

}
