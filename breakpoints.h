#ifndef BREAKPOINTS_H
#define BREAKPOINTS_H
#include <stdlib.h>
#include <stdio.h>

typedef struct
{
   long address;
   char original_opcode;
} breakpoint_t;

typedef struct node
{
   breakpoint_t *breakpoint;
   struct node *next;
} node_t;

typedef struct
{
   node_t *head;
   int size;
} list_t;

#endif