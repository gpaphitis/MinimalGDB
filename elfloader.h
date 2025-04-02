#ifndef ELFLOADER_H
#define ELFLOADER_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>

/**
 * Initializes libelf engine.
 */
int initialize_elf_engine(char *filename);
/**
 * Returns symbol, if found, for given address.
 */
char *get_symbol(long address);
/**
 * Returns address, if found, for given symbol
 */
long get_symbol_value(const char *symbol);
/**
 * Frees all used resources
 */
void destroy_elf_loader();

#endif