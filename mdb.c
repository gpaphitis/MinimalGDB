/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>

#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

/* Custom */
#include "breakpoints.h"
#include "elfloader.h"
#include "disassembler.h"
#include "arguments.h"

#define TOOL "mdb"

#define die(...)                                \
    do                                          \
    {                                           \
        fprintf(stderr, TOOL ": " __VA_ARGS__); \
        fputc('\n', stderr);                    \
        exit(EXIT_FAILURE);                     \
    } while (0)

#define CHILD_BREAKPOINT 1
#define CHILD_EXIT 2
#define MAX_INSN_SIZE 15
#define MAX_DISAS_INSN_COUNT 11

list_t *breakpoints;
breakpoint_t *last_hit_breakpoint;

enum child_state_t
{
    LOADED,
    EXECUTING,
    EXITED
} child_state;

/**
 * Creates a buffer for at least count instructions starting from address.
 */
size_t get_instruction_buffer(unsigned char **buffer, pid_t pid, long address, size_t count);
/**
 * Single step over specified number of steps and disassembles at the end.
 */
int process_step(pid_t pid, int steps);
/**
 * Disassembles following instructions from breakpoint reached.
 */
void process_inspect(pid_t pid, struct user_regs_struct *regs, breakpoint_t *breakpoint);
/**
 * Checks if execution was paused due to a software breakpoint.
 */
int check_if_breakpoint(pid_t pid, struct user_regs_struct *regs);
/**
 * Unsets all breakpoints.
 */
void clear_breakpoints(pid_t pid);
/**
 * Deletes breakpoint at index.
 */
void delete_breakpoint(pid_t pid, int index);
/**
 * Processes breakpoint execution paused on.
 * Prints breakpoint information, disassembles and switches breakpoint with original code.
 */
breakpoint_t *serve_breakpoint(pid_t pid);
/**
 * Reapplies breakpoint to instruction stream.
 */
void reset_breakpoint(pid_t pid, breakpoint_t *breakpoint);
/**
 * Removes breakpoint at index from instruction stream.
 */
void unset_breakpoint(pid_t pid, int index);
/**
 * Creates and sets new breakpoint at address.
 * If symbol is not given then it tries to find symbol associated with address.
 */
void set_breakpoint(pid_t pid, long addr, const char *symbol);
/**
 * Creates and sets new breakpoint at given symbol.
 * If symbol doesn't exist then returns -1.
 */
int set_symbol_breakpoint(pid_t pid, const char *symbol);
/**
 * Continues child execution.
 * Reapplies breakpoint execution paused on and pauses at the next reached breakpoint
 * or when the child finishes.
 */
int continue_execution(pid_t pid);
/**
 * Starts child execution.
 * Pauses at first reached breakpoint or when the child finishes.
 */
int execute(pid_t pid);
pid_t reload_child(pid_t child_pid, char **argv);
pid_t load_child(char **argv);
char *get_command();
void clear_input_buffer();
int confirm_choice(char *dialog);

size_t get_instruction_buffer(unsigned char **buffer, pid_t pid, long address, size_t count)
{
    *buffer = malloc(MAX_INSN_SIZE * count);
    size_t bytes_read = 0;
    while (bytes_read < MAX_INSN_SIZE * count)
    {
        long word = ptrace(PTRACE_PEEKDATA, pid, address + bytes_read, NULL);
        if (word == -1 && errno != 0)
        {
            free(*buffer);
            die("(peekdata) %s", strerror(errno));
        }

        // Copy the word to the buffer byte-by-byte
        for (size_t i = 0; i < sizeof(word) && bytes_read + i < MAX_INSN_SIZE * MAX_DISAS_INSN_COUNT; i++)
        {
            (*buffer)[bytes_read + i] = (word >> (i * 8)) & 0xFF;
        }

        bytes_read += sizeof(word);
    }
    return bytes_read;
}

int process_step(pid_t pid, int steps)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        if (errno == ESRCH)
        {
            /* System call was exit; so we need to end.  */
            fprintf(stderr, "\n");
            return CHILD_EXIT;
        }
        die("%s", strerror(errno));
    }
    for (int i = 0; i < steps; i++)
    {
        breakpoint_t *reached_breakpoint = get_breakpoint_by_address(breakpoints, regs.rip);
        // About to execute a breakpoint
        if (reached_breakpoint != NULL)
        {
            // Replace breakpoint with actual code, execute and reset the breakpoint
            if (ptrace(PTRACE_POKEDATA, pid, (void *)reached_breakpoint->address, (void *)reached_breakpoint->previous_code) == -1)
                die("(pokedata) %s", strerror(errno));
            if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
                die("(singlestep) %s", strerror(errno));
            waitpid(pid, 0, 0);
            reset_breakpoint(pid, reached_breakpoint);
        }
        else
        {
            if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
                die("(singlestep) %s", strerror(errno));
            waitpid(pid, 0, 0);
        }

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        {
            /* System call was exit; so we need to end.  */
            if (errno == ESRCH)
            {
                fprintf(stderr, "\n");
                return CHILD_EXIT;
            }
            die("%s", strerror(errno));
        }
    }
    unsigned char *buffer = NULL;
    size_t bytes_read = get_instruction_buffer(&buffer, pid, regs.rip, MAX_DISAS_INSN_COUNT);
    disas(breakpoints, (unsigned char *)buffer, bytes_read, regs.rip, 0, MAX_DISAS_INSN_COUNT);
    free(buffer);
    return 0;
}

void process_inspect(pid_t pid, struct user_regs_struct *regs, breakpoint_t *breakpoint)
{
    unsigned char *buffer = NULL;
    size_t bytes_read = get_instruction_buffer(&buffer, pid, breakpoint->address, MAX_DISAS_INSN_COUNT);
    disas(breakpoints, (unsigned char *)buffer, bytes_read, breakpoint->address, 0, MAX_DISAS_INSN_COUNT);
    free(buffer);
}

int check_if_breakpoint(pid_t pid, struct user_regs_struct *regs)
{
    // Get opcode of previous instruction(the one that caused pause)
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs->rip - 1, 0);
    if (current_ins == -1)
        die("(peekdata) %s", strerror(errno));
    current_ins &= 0x00000000000000FF;

    // Check if opcode is a software breakpoint
    return current_ins == 0xcc;
}

void clear_breakpoints(pid_t pid)
{
    int total = get_num_breakpoints(breakpoints);
    for (int i = 0; i < total; i++)
    {
        unset_breakpoint(pid, i);
    }
    remove_all_breakpoints(breakpoints);
}

void delete_breakpoint(pid_t pid, int index)
{
    unset_breakpoint(pid, index);
    remove_breakpoint(breakpoints, index);
}

breakpoint_t *serve_breakpoint(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    breakpoint_t *breakpoint = get_breakpoint_by_address(breakpoints, regs.rip - 1);
    fprintf(stderr, "Breakpoint \x1b[34m0x%lx\x1b[0m", breakpoint->address);
    if (breakpoint->symbol != NULL)
        fprintf(stderr, " in \x1b[33m%s\x1b[0m", breakpoint->symbol);
    fprintf(stderr, "\n");

    // Replace breakpoint with original instruction and RIP to corrected instruction
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)breakpoint->previous_code) == -1)
        die("(pokedata) %s", strerror(errno));
    regs.rip = breakpoint->address;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));

    process_inspect(pid, &regs, breakpoint);
    return breakpoint;
}

void reset_breakpoint(pid_t pid, breakpoint_t *breakpoint)
{
    long trap = (breakpoint->previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));
}

void unset_breakpoint(pid_t pid, int index)
{
    breakpoint_t *breakpoint = get_breakpoint(breakpoints, index);
    if (breakpoint == NULL)
        return;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)breakpoint->previous_code) == -1)
        die("(pokedata) %s", strerror(errno));
    if (last_hit_breakpoint != NULL && breakpoint->address == last_hit_breakpoint->address)
        last_hit_breakpoint = NULL;
}

void set_breakpoint(pid_t pid, long addr, const char *symbol)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (previous_code == -1)
    {
        fprintf(stderr, "Cannot access memory at \x1b[34m0x%lx\x1b[0m\n", addr);
        fprintf(stderr, "Cannot set breakpoint at \x1b[34m0x%lx\x1b[0m\n", addr);
        return;
    }

    // If symbol not given, try and find it
    symbol = (symbol != NULL) ? symbol : get_symbol(addr);
    int index = add_breakpoint(breakpoints, addr, previous_code, symbol);
    if (index >= 0)
    {
        fprintf(stderr, "Breakpoint %d at \x1b[34m0x%lx\x1b[0m", index, addr);
        if (symbol != NULL)
            fprintf(stderr, " \x1b[33m<%s>\x1b[0m", symbol);
        fprintf(stderr, "\n");

        long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
        if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
            die("set_breakpoint(pokedata) %s", strerror(errno));
    }
    else
        fprintf(stderr, "Cannot set breakpoint at \x1b[34m0x%lx\x1b[0m\n", addr);
}

int set_symbol_breakpoint(pid_t pid, const char *symbol)
{
    long addr = get_symbol_value(symbol);
    if (addr == -1)
        return -1;
    set_breakpoint(pid, addr, symbol);
    return 0;
}

int continue_execution(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        /* System call was exit; so we need to end.  */
        if (errno == ESRCH)
        {
            fprintf(stderr, "\n");
            return CHILD_EXIT;
        }
        die("%s", strerror(errno));
    }
    if (last_hit_breakpoint != NULL)
    {
        // We are continuing from the breakpoint we paused on so fix it and execute
        if (regs.rip == last_hit_breakpoint->address)
        {
            if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
                die("(singlestep) %s", strerror(errno));
            waitpid(pid, 0, 0);
        }

        // Reset last hit breakpoint breakpoint
        reset_breakpoint(pid, last_hit_breakpoint);
    }
    int status = 0;
    while (1)
    {
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
            die("%s", strerror(errno));
        if (waitpid(pid, &status, 0) == -1)
            die("%s", strerror(errno));

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        {
            /* System call was exit; so we need to end.  */
            if (errno == ESRCH)
            {
                fprintf(stderr, "\n");
                return CHILD_EXIT;
            }
            die("%s", strerror(errno));
        }
        if (check_if_breakpoint(pid, &regs))
        {
            last_hit_breakpoint = serve_breakpoint(pid);
            return CHILD_BREAKPOINT;
        }
    }
}

int execute(pid_t pid)
{
    int status = 0;
    while (1)
    {
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
            die("%s", strerror(errno));
        /* Block until process state change (i.e., next event). */
        if (waitpid(pid, &status, 0) == -1)
            die("%s", strerror(errno));

        /* Collect information about the system call.  */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        {
            if (errno == ESRCH)
            {
                /* System call was exit; so we need to end.  */
                fprintf(stderr, "\n");
                return CHILD_EXIT;
            }
            die("%s", strerror(errno));
        }
        if (check_if_breakpoint(pid, &regs))
        {
            last_hit_breakpoint = serve_breakpoint(pid);
            return CHILD_BREAKPOINT;
        }
    }
}

pid_t reload_child(pid_t child_pid, char **argv)
{
    kill(child_pid, SIGKILL);
    waitpid(child_pid, NULL, 0);
    pid_t pid = load_child(argv);
    for (int i = 0; i < breakpoints->size; i++)
        reset_breakpoint(pid, get_breakpoint(breakpoints, i));
    return pid;
}

pid_t load_child(char **argv)
{
    pid_t pid = fork();
    switch (pid)
    {
    case -1:
        die("%s", strerror(errno));
    case 0:
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], argv + 1);
        die("%s", strerror(errno));
    }
    waitpid(pid, 0, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    child_state = LOADED;
    return pid;
}

char *get_command()
{
    char *input = malloc(60 * sizeof(char));
    if (fgets(input, 60 * sizeof(char), stdin) == NULL)
    {
        fprintf(stderr, "Error reading input.\n");
        return NULL;
    }
    if (input[strlen(input) - 1] != '\n')
    {
        clear_input_buffer();
        fprintf(stderr, "Input too long\n");
        return NULL;
    }
    size_t len = strlen(input);
    if (len > 1 && input[len - 1] == '\n')
    {
        input[len - 1] = '\0';
        return input;
    }
    fprintf(stderr, "Enter command\n");
    return NULL;
}

void clear_input_buffer()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
}

int confirm_choice(char *dialog)
{
    char input = '\0';
    while (1)
    {
        fprintf(stderr, "%s", dialog);
        fprintf(stderr, "(y or n) ");
        if (scanf(" %c", &input) != 1)
        {
            clear_input_buffer();
            continue;
        }

        if (input == 'y' || input == 'n')
        {
            clear_input_buffer();
            break;
        }

        fprintf(stderr, "Please answer y or n.\n");
        // Clear input buffer
        clear_input_buffer();
    }
    return input == 'y' ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("mdb <program>: %d", argc);
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    if (initialize_elf_engine(argv[1]) == -1)
        die("(elf initialize) %s", elf_errmsg(-1));

    if (initialize_disassembler() == -1)
        die("(disassembler initialize) %s", elf_errmsg(-1));

    pid_t pid = load_child(argv);

    breakpoints = list_init();
    char **current_args = copy_args(argv);
    size_t args_size = argc;
    char *command = NULL;
    while (1)
    {
        printf("(mdb) ");
        command = get_command(command);
        if (command == NULL)
            continue;
        char *token = strtok(command, " ");
        if (!strcmp(token, "r"))
        {
            if (child_state == EXECUTING)
            {
                if (confirm_choice("The program being debugged has been started already.\nStart it from the beginning? "))
                {
                    if (*(command + strlen(token) + 1) != '\0')
                        args_size = replace_args(command + strlen(token) + 1, &current_args);
                    pid = reload_child(pid, current_args);
                }
                else
                    continue;
            }
            else
            {
                if (*(command + strlen(token) + 1) != '\0')
                    args_size = replace_args(command + strlen(token) + 1, &current_args);
                pid = reload_child(pid, current_args);
            }
            fprintf(stderr, "Starting program: \033[0;32m%s ", current_args[1]);
            for (int i = 2; i < args_size; i++)
                fprintf(stderr, "%s ", current_args[i]);
            fprintf(stderr, "\033[0m\n");
            child_state = EXECUTING;
            if (execute(pid) == CHILD_EXIT)
                child_state = EXITED;
        }
        else if (!strcmp(token, "c"))
        {
            if (child_state != EXECUTING)
                printf("Program has not started or has finished\n");
            else
            {
                if (continue_execution(pid) == CHILD_EXIT)
                    child_state = EXITED;
            }
        }
        else if (!strcmp(token, "si"))
        {
            if (child_state != EXECUTING)
                printf("Program has not started or has finished\n");
            else
            {
                char *error = NULL;
                token = strtok(NULL, " ");
                int steps = strtol(token, &error, 10);
                if (*error != '\0')
                {
                    fprintf(stderr, "Enter a valid number\n");
                    continue;
                }
                if (process_step(pid, steps) == CHILD_EXIT)
                    child_state = EXITED;
            }
        }
        else if (!strcmp(token, "b"))
        {
            if (child_state == EXITED)
                pid = reload_child(pid, current_args);
            token = strtok(NULL, " "); // Get the next token
            long address = 0;
            if (token[0] == '*')
            {
                token = strtok(token, "*");
                address = (long)strtol(token, NULL, 16);
                set_breakpoint(pid, address, NULL);
            }
            else
            {
                if (set_symbol_breakpoint(pid, token) == -1)
                    printf("Function \"%s\" not defined.\n", token);
            }
        }
        else if (!strcmp(token, "l"))
            print_list(breakpoints);
        else if (!strcmp(token, "d"))
        {
            token = strtok(NULL, " "); // Get the next token
            if (token == NULL)
                child_state == EXITED ? remove_all_breakpoints(breakpoints) : clear_breakpoints(pid);
            else
            {
                char *error = NULL;
                int index = (int)strtol(token, &error, 10);
                if (*error != '\0')
                {
                    fprintf(stderr, "Enter a valid number\n");
                    continue;
                }
                else if (index >= get_num_breakpoints(breakpoints))
                {
                    fprintf(stderr, "Index out of bounds\n");
                    continue;
                }
                if (child_state == EXITED)
                    remove_breakpoint(breakpoints, index);
                delete_breakpoint(pid, index);
            }
        }
        else if (!strcmp(token, "quit"))
        {
            free(command);
            char *dialog = malloc(100);
            sprintf(dialog, "A debugging session is active.\n\n\tInferior 1 [process %d] will be killed.\n\nQuit anyway?", pid);
            if (child_state == EXECUTING && !confirm_choice(dialog))
            {
                free(dialog);
                continue;
            }
            free(dialog);
            break;
        }
        else if (!strcmp(token, "clear"))
        {
            fprintf(stderr, "\033[H\033[J");
            fflush(stderr);
        }
        else
        {
            fprintf(stderr,
                    "Commands:\n"
                    "b *<address>/<symbol>\tSets breakpoint\n"
                    "l\t\t\tPrints list of set breakpoints\n"
                    "r <args>\t\tChild (re)starts execution with given arguments. If arguments are omitted, previous ones will be used\n"
                    "c\t\t\tChild continues execution\n"
                    "si <steps>\t\tSingle steps <steps> instruction, 1 if omitted\n"
                    "d [index]\t\tDelete breakpoint at index, if not defined deletes all\n"
                    "quit\t\t\tExits\n"
                    "clear\t\t\tClears screen\n");
        }
        free(command);
    }
    free_args(current_args);
    list_destroy(breakpoints);
    destroy_disassembler();
    destroy_elf_loader();
}