#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <capstone/capstone.h>
#include "breakpoints.h"
#include "elfloader.h"

/**
 * Initializes Capstone engine.
 */
int initialize_disassembler();
/**
 * Disassembles at most specified amount of instructions from buffer or until end of function is found.
 * If breakpoint is found then replaces with original opcode 
 */
void disas(list_t *breakpoints, unsigned char *buffer, unsigned int size, long address, long offset, int count);
/**
 * Frees all used resources.
 */
void destroy_disassembler();

#endif