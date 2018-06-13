#pragma once

#include <stdio.h>
#include "config.h"

#ifdef __DEBUG
	#define debug printf
#else
	#define debug nothing
#endif

void print_memory(unsigned char* memory, size_t size);

void nothing(char* arg, ...);
