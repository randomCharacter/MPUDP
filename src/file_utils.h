#pragma once

#include <stdio.h>
#include <stdlib.h>

size_t load_file_to_memory(FILE *f, unsigned char **buffer);

void load_memory_to_file(FILE *f, unsigned char *buffer, size_t size);
