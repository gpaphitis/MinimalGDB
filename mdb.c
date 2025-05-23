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
// #include "arguments.h"
#include "inputparser.h"
#include "definitions.h"

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
#define MAX_INPUT_SIZE 60
#define WORD_LENGTH 0x4

list_t *breakpoints;
breakpoint_t *last_hit_breakpoint;
child_state_t child_state;

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
 * Prints register values
 */
void print_registers(pid_t pid);
/**
 * Prints words from memory
 */
void print_memory(pid_t pid, uint64_t start_address, uint64_t num_words);
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
pid_t execute(pid_t pid);
/**
 * Kills currently running child and restarts it.
 * Reapplies all currently existing breakpoints.
 */
pid_t reload_child(pid_t child_pid, char **argv);
/**
 * Loads child.
 */
pid_t load_child(char **argv);
/**
 * Gets command from user.
 */
char *get_input();
/**
 * Flushes input buffer.
 */
void clear_input_buffer();

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
            long current_code = ptrace(PTRACE_PEEKDATA, pid, (void *)reached_breakpoint->address, 0);
            if (current_code == -1)
            {
                fprintf(stderr, "Cannot access memory at \x1b[34m0x%lx\x1b[0m\n", reached_breakpoint->address);
                die("(peekdata) %s", strerror(errno));
            }
            // Replace breakpoint with actual code, execute and reset the breakpoint
            if (ptrace(PTRACE_POKEDATA, pid, (void *)reached_breakpoint->address, (void *)((current_code & 0xFFFFFFFFFFFFFF00) | reached_breakpoint->previous_code)) == -1)
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

    long current_code = ptrace(PTRACE_PEEKDATA, pid, (void *)breakpoint->address, 0);
    if (current_code == -1)
    {
        fprintf(stderr, "Cannot access memory at \x1b[34m0x%lx\x1b[0m\n", breakpoint->address);
        die("(peekdata) %s", strerror(errno));
    }
    // Replace breakpoint with original instruction and RIP to corrected instruction
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)((current_code & 0xFFFFFFFFFFFFFF00) | breakpoint->previous_code)) == -1)
        die("(pokedata) %s", strerror(errno));
    regs.rip = breakpoint->address;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));

    process_inspect(pid, &regs, breakpoint);
    return breakpoint;
}

void disassemble_position(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));
    unsigned char *buffer = NULL;
    size_t bytes_read = get_instruction_buffer(&buffer, pid, regs.rip, MAX_DISAS_INSN_COUNT);
    disas(breakpoints, (unsigned char *)buffer, bytes_read, regs.rip, 0, MAX_DISAS_INSN_COUNT);
    free(buffer);
}

void reset_breakpoint(pid_t pid, breakpoint_t *breakpoint)
{
    long current_code = ptrace(PTRACE_PEEKDATA, pid, (void *)breakpoint->address, 0);
    if (current_code == -1)
    {
        fprintf(stderr, "Cannot access memory at \x1b[34m0x%lx\x1b[0m\n", breakpoint->address);
        return;
    }
    long trap = (current_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));
}

void unset_breakpoint(pid_t pid, int index)
{
    breakpoint_t *breakpoint = get_breakpoint(breakpoints, index);
    if (breakpoint == NULL)
        return;
    long current_code = ptrace(PTRACE_PEEKDATA, pid, (void *)breakpoint->address, 0);
    if (current_code == -1)
    {
        fprintf(stderr, "Cannot access memory at \x1b[34m0x%lx\x1b[0m\n", breakpoint->address);
        return;
    }
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)((current_code & 0xFFFFFFFFFFFFFF00) | breakpoint->previous_code)) == -1)
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
    int index = add_breakpoint(breakpoints, addr, (unsigned char)(previous_code & 0xFF), symbol);
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

void print_registers(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        if (errno == ESRCH)
        {
            return;
        }
        die("%s", strerror(errno));
    }
    printf("rax\t\t0x%-20llx%llu\n", regs.rax, regs.rax);
    printf("rbx\t\t0x%-20llx%llu\n", regs.rbx, regs.rbx);
    printf("rcx\t\t0x%-20llx%llu\n", regs.rcx, regs.rcx);
    printf("rdx\t\t0x%-20llx%llu\n", regs.rdx, regs.rdx);
    printf("rsi\t\t0x%-20llx%llu\n", regs.rsi, regs.rsi);
    printf("rdi\t\t0x%-20llx%llu\n", regs.rdi, regs.rdi);
    printf("rbp\t\t0x%-20llx%llu\n", regs.rbp, regs.rbp);
    printf("rsp\t\t0x%-20llx%llu\n", regs.rsp, regs.rsp);
    printf("r8\t\t0x%-20llx%llu\n", regs.r8, regs.r8);
    printf("r9\t\t0x%-20llx%llu\n", regs.r9, regs.r9);
    printf("r10\t\t0x%-20llx%llu\n", regs.r10, regs.r10);
    printf("r10\t\t0x%-20llx%llu\n", regs.r10, regs.r10);
    printf("r11\t\t0x%-20llx%llu\n", regs.r11, regs.r11);
    printf("r12\t\t0x%-20llx%llu\n", regs.r12, regs.r12);
    printf("r13\t\t0x%-20llx%llu\n", regs.r13, regs.r13);
    printf("r14\t\t0x%-20llx%llu\n", regs.r14, regs.r14);
    printf("r15\t\t0x%-20llx%llu\n", regs.r15, regs.r15);
    printf("rip\t\t0x%-20llx%llu\n", regs.rip, regs.rip);
    printf("eflags\t\t0x%-20llx\n", regs.eflags);
    printf("cs\t\t0x%-20llx%llu\n", regs.cs, regs.cs);
    printf("ss\t\t0x%-20llx%llu\n", regs.ss, regs.ss);
    printf("ds\t\t0x%-20llx%llu\n", regs.ds, regs.ds);
    printf("es\t\t0x%-20llx%llu\n", regs.es, regs.es);
    printf("fs\t\t0x%-20llx%llu\n", regs.fs, regs.fs);
    printf("gs\t\t0x%-20llx%llu\n", regs.gs, regs.gs);
    printf("fs_base\t\t0x%-20llx%llu\n", regs.fs_base, regs.fs_base);
    printf("gs_base\t\t0x%-20llx%llu\n", regs.gs_base, regs.gs_base);
}

void print_memory(pid_t pid, uint64_t start_address, uint64_t num_words)
{
    uint64_t buffer_size = WORD_LENGTH * num_words;
    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    size_t bytes_read = 0;
    while (bytes_read < buffer_size)
    {
        long word = ptrace(PTRACE_PEEKDATA, pid, start_address + bytes_read, NULL);
        if (word == -1 && errno != 0)
        {
            free(buffer);
            die("(peekdata) %s", strerror(errno));
        }

        // Copy the word to the buffer byte-by-byte
        for (size_t i = 0; i < sizeof(word) && bytes_read + i < buffer_size; i++)
        {
            buffer[bytes_read + i] = (word >> (i * 8)) & 0xFF;
        }

        bytes_read += sizeof(word);
    }
    for (int i = 0; i < num_words; i++)
    {
        printf("0x%lx\t", start_address + i * WORD_LENGTH);
        uint32_t word = 0;
        for (int j = 0; j < WORD_LENGTH; j++)
            word |= ((uint32_t)buffer[i * WORD_LENGTH + j] << (j * 8));
        printf("0x%x\n", word);
    }
    free(buffer);
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

pid_t execute(pid_t pid)
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

        char *file = argv[1];
        // If no '/' in filename, assume it's in current dir
        if (!strchr(file, '/'))
        {
            char *path = malloc(strlen(file) + 3);
            sprintf(path, "./%s", file);
            file = path;
        }
        execvp(file, argv + 1);
        free(file);
        die("%s", strerror(errno));
    }
    waitpid(pid, 0, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    child_state = LOADED;
    return pid;
}

char *get_input()
{
    char *input = malloc(MAX_INPUT_SIZE * sizeof(char));
    while (1)
    {
        fprintf(stderr, "(mdb) ");
        if (fgets(input, MAX_INPUT_SIZE * sizeof(char), stdin) == NULL)
        {
            memset(input, 0, MAX_INPUT_SIZE);
            fprintf(stderr, "Error reading input.\n");
            continue;
        }

        if (input[strlen(input) - 1] != '\n')
        {
            // Flush stdin to remove extra characters for next input
            clear_input_buffer();
            memset(input, 0, MAX_INPUT_SIZE);
            fprintf(stderr, "Input too long\n");
            continue;
        }

        size_t len = strlen(input);
        if (len > 1 && input[len - 1] == '\n')
        {
            input[len - 1] = '\0';
            return input;
        }
        // No input was given
        fprintf(stderr, "Enter command\n");
    }
    return NULL;
}

void clear_input_buffer()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
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
    char *input = NULL;
    while (1)
    {
        command = get_input();
        input = (char *)malloc(strlen(command) + 1);
        strncpy(input, command, strlen(command));
        input[strlen(command)] = '\0';
        input_t *inputs = parse_input(input, child_state, &current_args, &args_size, pid);
        if (inputs == NULL)
            continue;
        if (!strcmp(inputs->command, "r"))
        {
            pid = reload_child(pid, current_args);
            fprintf(stderr, "Starting program: \033[0;32m%s ", current_args[1]);
            for (int i = 2; i < args_size; i++)
                fprintf(stderr, "%s ", current_args[i]);
            fprintf(stderr, "\033[0m\n");
            child_state = EXECUTING;
            if (execute(pid) == CHILD_EXIT)
                child_state = EXITED;
        }
        else if (!strcmp(inputs->command, "c"))
        {
            if (child_state != EXECUTING)
                fprintf(stderr, "Program has not started or has finished\n");
            else
            {
                if (continue_execution(pid) == CHILD_EXIT)
                    child_state = EXITED;
            }
        }
        else if (!strcmp(inputs->command, "si"))
        {
            if (child_state != EXECUTING)
                fprintf(stderr, "Program has not started or has finished\n");
            else
            {
                int steps = atoi(inputs->params[0]);
                if (process_step(pid, steps) == CHILD_EXIT)
                    child_state = EXITED;
            }
        }
        else if (!strcmp(inputs->command, "b"))
        {
            if (child_state == EXITED)
                pid = reload_child(pid, current_args);
            if (!strcmp(inputs->params[0], "address"))
            {
                long address = (long)strtol(inputs->params[1], NULL, 16);
                set_breakpoint(pid, address, NULL);
                continue;
            }
            if (set_symbol_breakpoint(pid, inputs->params[1]) == -1)
                fprintf(stderr, "Function \"%s\" not defined.\n", inputs->params[1]);
        }
        else if (!strcmp(inputs->command, "i"))
        {
            if (!strcmp(inputs->params[0], "b"))
                print_list(breakpoints);
            else if (!strcmp(inputs->params[0], "r"))
            {
                if (child_state != EXECUTING)
                {
                    printf("Program has no registers now.\n");
                    printf("he program has no registers now.\n");
                    continue;
                }
                print_registers(pid);
            }
            else
            {
                fprintf(stderr, "Invalid option\n");
            }
        }
        else if (!strcmp(inputs->command, "d"))
        {
            if (inputs->params == NULL)
                child_state == EXITED ? remove_all_breakpoints(breakpoints) : clear_breakpoints(pid);
            else
            {
                char *error = NULL;
                int index = (int)strtol(inputs->params[0], &error, 10);
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
        else if (!strcmp(inputs->command, "x"))
        {
            if (!strcmp(inputs->params[0], "error"))
                continue;
            char *error = NULL;
            long words = strtol(inputs->params[0], &error, 10);
            if (*error != '\0')
            {
                fprintf(stderr, "Enter a valid number\n");
                continue;
            }
            long start_address = strtol(inputs->params[1], &error, 16);
            if (*error != '\0')
            {
                fprintf(stderr, "Enter a valid address\n");
                continue;
            }
            print_memory(pid, start_address, words);
        }
        else if (!strcmp(inputs->command, "disas"))
        {
            disassemble_position(pid);
        }
        else if (!strcmp(inputs->command, "quit"))
        {
            if (inputs->params != NULL && !strcmp(inputs->params[0], "continue"))
                continue;
            break;
        }
        else if (!strcmp(inputs->command, "clear"))
        {
            fprintf(stderr, "\033[H\033[J");
            fflush(stderr);
        }
        else
        {
            fprintf(stderr,
                    "Commands:\n"
                    "b *<address>/<symbol>\tSets breakpoint\n"
                    "i [i|b]\t\t\tPrints list of set breakpoints[b] or register values[r]\n"
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