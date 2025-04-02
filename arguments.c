#include "arguments.h"

static int count_args(const char *str)
{
   int count = 0;
   int in_token = 0; // Track if inside a word

   while (*str)
   {
      if (*str == ' ')
      {
         in_token = 0;
      }
      else if (!in_token)
      {
         in_token = 1;
         count++;
      }
      str++;
   }
   return count;
}

void free_args(char **argv)
{
   if (argv == NULL)
      return;
   size_t size = 1;
   while (argv[size] != NULL)
   {
      free(argv[size]);
      size++;
   }
   free(argv);
}

size_t replace_args(char *args, char ***argv)
{

   int total_args = count_args(args);
   char **new_argv = malloc((total_args + 3) * sizeof(char *));
   new_argv[1] = malloc(strlen((*argv)[1]) + 1);
   strncpy(new_argv[1], (*argv)[1], strlen((*argv)[1]));
   new_argv[1][strlen((*argv)[1])] = '\0';
   int i = 2;
   char *token = strtok(args, " ");
   while (token != NULL)
   {
      new_argv[i] = malloc(strlen(token) + 1);
      strncpy(new_argv[i], token, strlen(token));
      new_argv[i][strlen(token)] = '\0';
      token = strtok(NULL, " ");
      i++;
   }
   new_argv[total_args + 2] = NULL;
   free_args(*argv);
   *argv = new_argv;
   return total_args + 2;
}
char **copy_args(char **args)
{

   size_t size = 1;
   while (args[size] != NULL)
   {
      size++;
   }
   char **new_args = malloc((size + 1) * sizeof(char *));
   for (int i = 1; i < size; i++)
   {
      new_args[i] = malloc(strlen(args[i]) + 1);
      strncpy(new_args[i], args[i], strlen(args[i]));
      new_args[i][strlen(args[i])] = '\0';
   }
   new_args[size] = NULL;
   return new_args;
}
