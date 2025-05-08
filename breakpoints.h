#ifndef BREAKPOINTS_H
#define BREAKPOINTS_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
   long address;
   unsigned char previous_code;
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

/**
 * Initializes a new breakpoint linked list.
 */
list_t *list_init();
/**
 * Creates and adds new breakpoint.
 */
int add_breakpoint(list_t *list, long address, unsigned char previous_code, const char *symbol);
/**
 * Removes breakpoint from.
 */
void remove_breakpoint(list_t *list, int index);
/**
 * Returns breakpoint at index.
 */
breakpoint_t *get_breakpoint(list_t *list, int index);
/**
 * Returns breakpoint with specified address.
 */
breakpoint_t *get_breakpoint_by_address(list_t *list, long address);
/**
 * Remall breakpoints.
 */
void remove_all_breakpoints(list_t *list);
/**
 * Prints breakpoint list.
 */
void print_list(list_t *list);
/**
 * Returns number of breakpoints.
 */
int get_num_breakpoints(list_t *list);
/**
 * Frees all used resources.
 */
void list_destroy(list_t *list);

#endif