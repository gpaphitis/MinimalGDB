#ifndef ARGUMENTS_H
#define ARGUMENTS_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * Converts single string args to an argv structure replacing previous one.
 */
size_t replace_args(char *args, char ***argv);
/**
 * Copies args to new array.
 */
char **copy_args(char **args);
/**
 * Frees args.
 */
void free_args(char **argv);

#endif