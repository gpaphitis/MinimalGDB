#ifndef INPUTPARSER_H
#define INPUTPARSER_H
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

// #include "arguments.h"
#include "definitions.h"

typedef struct
{
    char *command;
    char **params;
} input_t;

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
input_t *parse_input(char *input, child_state_t child_state, char ***current_args, size_t *args_size, pid_t pid);

#endif