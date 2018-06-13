#include "file_utils.h"

size_t load_file_to_memory(FILE *f, unsigned char **buffer) {
    size_t size;

    fseek(f, 0L, SEEK_END);
    size = ftell(f);
    fseek(f, 0L, SEEK_SET);

    *buffer = (unsigned char*) malloc(size);

    fread(*buffer, sizeof(unsigned char), size, f);

    return size;
}

void load_memory_to_file(FILE *f, unsigned char *buffer, size_t size) {
    fwrite(buffer, sizeof(unsigned char), size, f);
}
