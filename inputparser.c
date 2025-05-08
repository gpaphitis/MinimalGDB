#include "inputparser.h"

void set_command(input_t *inputs, char *command)
{
    inputs->command = (char *)malloc(strlen(command) + 1);
    strncpy(inputs->command, command, strlen(command));
    (inputs->command)[strlen(command)] = '\0';
}

void set_parameters(input_t *inputs, int count, ...)
{
    va_list args;
    va_start(args, count);
    inputs->params = (char **)malloc(count * sizeof(char *));
    for (int i = 0; i < count; i++)
    {
        char *val = va_arg(args, char *);
        inputs->params[i] = val;
    }
    va_end(args);
}

static void clear_input_buffer()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
}

static int confirm_choice(char *dialog)
{
    char input = '\0';
    while (1)
    {
        fprintf(stderr, "%s ", dialog);
        fprintf(stderr, "(y or n) ");
        if (scanf(" %c", &input) != 1)
        {
            clear_input_buffer();
            continue;
        }
        if (input == 'y' || input == 'n')
            break;

        clear_input_buffer();
        fprintf(stderr, "Please answer y or n.\n");
    }
    clear_input_buffer();
    return input == 'y' ? 1 : 0;
}

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
    char **new_argv = (char **)malloc((total_args + 3) * sizeof(char *));
    new_argv[1] = (char *)malloc(strlen((*argv)[1]) + 1);
    strncpy(new_argv[1], (*argv)[1], strlen((*argv)[1]));
    new_argv[1][strlen((*argv)[1])] = '\0';
    int i = 2;
    char *token = strtok(args, " ");
    while (token != NULL)
    {
        new_argv[i] = (char *)malloc(strlen(token) + 1);
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
    char **new_args = (char **)malloc((size + 1) * sizeof(char *));
    for (int i = 1; i < size; i++)
    {
        new_args[i] = (char *)malloc(strlen(args[i]) + 1);
        strncpy(new_args[i], args[i], strlen(args[i]));
        new_args[i][strlen(args[i])] = '\0';
    }
    new_args[size] = NULL;
    return new_args;
}

size_t get_num_length(size_t num)
{
    size_t length = 0;
    while (num > 0)
    {
        num /= 10;
        length++;
    }
    return length;
}

input_t *parse_input(char *input, child_state_t child_state, char ***current_args, size_t *args_size, pid_t pid)
{
    // Input is composed of a command and an array of it's arguments
    input_t *inputs = (input_t *)malloc(sizeof(input_t));
    char *orig_input = (char *)malloc(strlen(input) + 1);
    strncpy(orig_input, input, strlen(input));
    orig_input[strlen(input)] = '\0';
    char *token = strtok(input, " ");

    if (!strcmp(token, "r"))
    {
        if (child_state == EXECUTING)
        {
            if (confirm_choice("The program being debugged has been started already.\nStart it from the beginning? "))
            {
                set_command(inputs, "r");
                if (*(orig_input + strlen(token) + 1) != '\0')
                {
                    *args_size = replace_args(orig_input + strlen(token) + 1, current_args);
                    return inputs;
                }
            }
            else
                return NULL;
        }
        set_command(inputs, "r");
        if (strlen(orig_input) > strlen(inputs->command))
            *args_size = replace_args(orig_input + strlen(token) + 1, current_args);
    }
    else if (!strcmp(token, "c"))
    {
        set_command(inputs, "c");
    }
    else if (!strcmp(token, "si"))
    {
        set_command(inputs, "si");
        if (child_state == EXECUTING)
        {
            char *error = NULL;
            token = strtok(NULL, " ");
            if (token != NULL)
            {
                strtol(token, &error, 10);
                if (*error != '\0')
                {
                    fprintf(stderr, "Enter a valid number\n");
                    return NULL;
                }
                set_parameters(inputs, 1, token);
            }
            else
                set_parameters(inputs, 1, "1");
        }
        return inputs;
    }
    else if (!strcmp(token, "b"))
    {
        set_command(inputs, "b");
        token = strtok(NULL, " "); // Get the next token
        if (token[0] == '*')
        {
            char *error = NULL;
            token = strtok(token, "*");
            strtol(token, &error, 16);
            if (*error != '\0')
            {
                fprintf(stderr, "Enter a valid address in hex\n");
                return NULL;
            }
            set_parameters(inputs, 2, "address", token);
        }
        else
        {
            set_parameters(inputs, 2, "symbol", token);
        }
        return inputs;
    }
    else if (!strcmp(token, "i"))
    {
        set_command(inputs, "i");
        token = strtok(NULL, " ");
        set_parameters(inputs, 1, token);
        return inputs;
    }
    else if (!strcmp(token, "d"))
    {
        set_command(inputs, "d");
        token = strtok(NULL, " "); // Get the next token
        if (token == NULL)
            return inputs;
        set_parameters(inputs, 1, token);
        return inputs;
    }
    else if (token[0] == 'x')
    {
        set_command(inputs, "x");
        char *inner_token = token;
        token = strtok(NULL, " ");
        inner_token = strtok(inner_token, "/");
        if (strcmp(inner_token, "x")) // Check that there is only 'x' before /
        {
            printf("Incorrect syntax\n");
            set_parameters(inputs, 1, "error");
            return inputs;
        }
        inner_token = strtok(NULL, "/");
        if (inner_token == NULL) // Check that there is only 'x' before /
        {
            printf("Incorrect syntax\n");
            set_parameters(inputs, 1, "error");
            return inputs;
        }
        int i = 0;
        int words = 0;
        while (i < strlen(inner_token) && inner_token[i] >= '0' && inner_token[i] <= '9')
        {
            if (words > 0)
                words *= 10;
            words = words + (int)(inner_token[i] - '0');
            i++;
        }
        words = (words == 0) ? 1 : words;
        if (i < strlen(inner_token))
        {
            printf("Incorrect syntax\n");
            set_parameters(inputs, 1, "error");
            return inputs;
        }
        if (token == NULL)
        {
            printf("Incorrect syntax\n");
            set_parameters(inputs, 1, "error");
            return inputs;
        }

        char *error = NULL;
        strtol(token, &error, 16);
        if (*error != '\0')
        {
            fprintf(stderr, "Enter a valid address\n");
            set_parameters(inputs, 1, "error");
            return inputs;
        }
        char *words_str = (char *)malloc(i + 1);
        sprintf(words_str, "%d", words);
        set_parameters(inputs, 2, words_str, token);
        return inputs;
    }
    else if (!strcmp(token, "disas"))
    {
        set_command(inputs, "disas");
        return inputs;
    }
    else if (!strcmp(token, "quit"))
    {
        set_command(inputs, "quit");
        char *dialog = (char *)malloc(100);
        sprintf(dialog, "A debugging session is active.\n\n\tInferior 1 [process %d] will be killed.\n\nQuit anyway?", pid);
        if (child_state == EXECUTING && !confirm_choice(dialog))
        {
            free(dialog);
            set_parameters(inputs, 1, "continue");
            return inputs;
        }
        free(dialog);
        return inputs;
    }
    else if (!strcmp(token, "clear"))
    {
        set_command(inputs, "clear");
        return inputs;
    }
    // else
    // {
    //     fprintf(stderr,
    //             "inputs:\n"
    //             "b *<address>/<symbol>\tSets breakpoint\n"
    //             "i [i|b]\t\t\tPrints list of set breakpoints[b] or register values[r]\n"
    //             "r <args>\t\tChild (re)starts execution with given arguments. If arguments are omitted, previous ones will be used\n"
    //             "c\t\t\tChild continues execution\n"
    //             "si <steps>\t\tSingle steps <steps> instruction, 1 if omitted\n"
    //             "d [index]\t\tDelete breakpoint at index, if not defined deletes all\n"
    //             "quit\t\t\tExits\n"
    //             "clear\t\t\tClears screen\n");
    // }
    // free(input);
    else
        return NULL;
    return inputs;
}