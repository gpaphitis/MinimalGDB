#ifndef ARGUMENTS_H
#define ARGUMENTS_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

size_t replace_args(char *args, char ***argv);
char **copy_args(char **args);
void free_args(char **argv);

#endif