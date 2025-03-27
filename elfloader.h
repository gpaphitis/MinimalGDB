#ifndef ELFLOADER_H
#define ELFLOADER_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>

int initialize_elf_engine(char *filename);
char *get_symbol(long address);
long get_symbol_value(const char *symbol);

#endif