#ifndef BREAKPOINTS_H
#define BREAKPOINTS_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
   long address;
   long previous_code;
   char *symbol;
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

list_t *list_init();
int add_breakpoint(list_t *list, long address, long previous_code, const char *symbol);
void remove_breakpoint(list_t *list, int index);
breakpoint_t *get_breakpoint(list_t *list, int index);
breakpoint_t *get_breakpoint_by_address(list_t *list, long address);
void remove_all(list_t *list);
void list_destroy(list_t *list);
void print_list(list_t *list);
int get_num_breakpoints(list_t *list);

#endif