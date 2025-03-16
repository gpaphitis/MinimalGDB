#include "breakpoints.h"

list_t *list_init()
{
   list_t *list = malloc(sizeof(list_t));
   list->head = NULL;
   list->size = 0;
   return list;
}

void print_breakpoint(breakpoint_t *breakpoint)
{
   printf("Address: %ld\tPrevious code: %ld\n", breakpoint->address, breakpoint->previous_code);
}

void add_breakpoint(list_t *list, long address, long previous_code)
{
   breakpoint_t *breakpoint = malloc(sizeof(breakpoint_t));
   if (breakpoint == NULL)
      perror("malloc() error for breakpoint_t in add_breakpoint()");
   breakpoint->address = address;
   breakpoint->previous_code = previous_code;
   node_t *new_node = malloc(sizeof(node_t));
   if (new_node == NULL)
      perror("malloc() error for node_t in add_breakpoint()");
   new_node->breakpoint = breakpoint;
   new_node->next = NULL;
   if (list->head == NULL)
   {
      list->head = new_node;
      list->size = 1;
      return;
   }
   node_t *last_node = list->head;
   for (; last_node->next != NULL; last_node = last_node->next)
      ;
   last_node->next = new_node;
   list->size++;
   return;
}

void delete_breakpoint(list_t *list, int index)
{
   if (index < 0 || index >= list->size || list->head == NULL)
      return;
   node_t *prev = NULL;
   node_t *target = list->head;
   for (int i = 0; i < index; i++)
   {
      prev = target;
      target = target->next;
   }
   if (prev != NULL)
      prev->next = target->next;
   else
      list->head = target->next;
   list->size--;
   free(target->breakpoint);
   free(target);
}
breakpoint_t *get_breakpoint(list_t *list, int index)
{
   if (index < 0 || index >= list->size || list->head == NULL)
      return NULL;
   node_t *target = list->head;
   for (int i = 0; i < index; i++)
   {
      target = target->next;
   }
   return target->breakpoint;
}
breakpoint_t *get_breakpoint_by_address(list_t *list, long address)
{
   if (address < 0 || list->head == NULL)
      return NULL;
   node_t *target = list->head;
   for (; target != NULL && target->breakpoint->address != address; target = target->next)
      ;
   return (target != NULL) ? target->breakpoint : NULL;
}

void clear_breakpoint(node_t *current)
{
   if (current->next != NULL)
      clear_breakpoint(current->next);
   free(current->breakpoint);
   free(current);
}

void clear_breakpoints(list_t *list)
{
   if (list->head == NULL)
      return;
   clear_breakpoint(list->head);
   list->head = NULL;
   list->size = 0;
   return;
}

void list_destroy(list_t *list)
{
   clear_breakpoints(list);
   free(list);
}

void print_list(list_t *list)
{
   int i = 0;
   if (list->head == NULL)
   {
      printf("No breakpoints set\n");
      return;
   }
   for (node_t *node = list->head; node != NULL; node = node->next)
   {
      printf("Breakpoint %d\n", i++);
      print_breakpoint(node->breakpoint);
   }
   printf("Size: %d\n", list->size);
}

#ifdef DEBUG
int main()
{
   list_t *list = list_init();
   add_breakpoint(list, 100, (char)10);
   add_breakpoint(list, 200, (char)20);
   add_breakpoint(list, 300, (char)30);
   print_list(list);
   list_destroy(list);
   return 0;
}
#endif