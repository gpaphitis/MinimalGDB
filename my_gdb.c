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

#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

/* Custom */
#include "breakpoints.h"
#include "elfloader.h"

#define TOOL "my_gdb"

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

list_t *breakpoints;
breakpoint_t *last_hit_breakpoint;
csh handle;

enum child_state_t
{
    LOADED,
    EXECUTING,
    EXITED
} child_state;

void print_ins(cs_insn *ins)
{

    fprintf(stderr, "0x%016lx:\t%s\t\t%s\n", ins->address, ins->mnemonic, ins->op_str);
}

size_t get_instruction_buffer(unsigned char **buffer, pid_t pid, long address, size_t count)
{
    *buffer = malloc(MAX_INSN_SIZE * count);
    size_t bytes_read = 0;
    while (bytes_read < MAX_INSN_SIZE * count)
    {
        // Read a word (sizeof(long)) from the child process memory
        long word = ptrace(PTRACE_PEEKDATA, pid, address + bytes_read, NULL);
        if (word == -1 && errno != 0)
        {
            free(*buffer);
            die("(peekdata) %s", strerror(errno));
        }

        // Copy the word to the buffer byte-by-byte
        for (size_t i = 0; i < sizeof(word) && bytes_read + i < MAX_INSN_SIZE * 11; i++)
        {
            (*buffer)[bytes_read + i] = (word >> (i * 8)) & 0xFF;
        }

        bytes_read += sizeof(word);
    }
    return bytes_read;
}

int is_cs_cflow_group(uint8_t g)
{
    return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

int is_cs_cflow_ins(cs_insn *ins)
{
    for (size_t i = 0; i < ins->detail->groups_count; i++)
    {
        if (is_cs_cflow_group(ins->detail->groups[i]))
        {
            return 1;
        }
    }
    return 0;
}

uint64_t get_cs_ins_immediate_target(cs_insn *ins)
{
    cs_x86_op *cs_op;

    for (size_t i = 0; i < ins->detail->groups_count; i++)
    {
        if (is_cs_cflow_group(ins->detail->groups[i]))
        {
            for (size_t j = 0; j < ins->detail->x86.op_count; j++)
            {
                cs_op = &ins->detail->x86.operands[j];
                if (cs_op->type == X86_OP_IMM)
                    return cs_op->imm;
            }
        }
    }
    return 0;
}

void disas(csh handle, unsigned char *buffer, unsigned int size, long address, long offset, int count)
{
    cs_insn *insn;
    size_t disassembled_count;

    disassembled_count = cs_disasm(handle, buffer, size, address + offset, count, &insn);
    int bytes_disassembled = 0;
    int breakpoint_found = 0;

    if (disassembled_count > 0)
    {
        size_t j;
        for (j = 0; j < disassembled_count; j++)
        {
            if (!strcmp(insn[j].mnemonic, "int3"))
            {
                breakpoint_found = 1;
                break;
            }
            if (j == 0 && offset == 0)
                fprintf(stderr, "=> ");
            char *symbol = get_symbol(insn[j].address);
            if (symbol == NULL)
                fprintf(stderr, "\x1b[34m0x%" PRIx64 "\x1b[0m:\t", insn[j].address);
            else
                fprintf(stderr, "\x1b[33m%s\x1b[0m :\t", symbol);
            fprintf(stderr, "%s\t\t%s", insn[j].mnemonic,
                    insn[j].op_str);
            if (is_cs_cflow_ins(&insn[j]))
            {
                uint64_t target = get_cs_ins_immediate_target(&insn[j]);
                char *symbol = get_symbol(target);
                if (symbol != NULL && strcmp(symbol, ""))
                    fprintf(stderr, " # <\x1b[33m%s\x1b[0m>", symbol);
            }
            fprintf(stderr, "\n");
            bytes_disassembled += insn[j].size;
            if (insn[j].id == X86_INS_RET)
                break;
        }
        cs_free(insn, disassembled_count);
        if (breakpoint_found)
        {
            breakpoint_t *disassembled_breakpoint = get_breakpoint_by_address(breakpoints, address + bytes_disassembled);
            buffer[bytes_disassembled] &= 0x00;
            buffer[bytes_disassembled] |= (disassembled_breakpoint->previous_code & 0xFF);
            disas(handle, &buffer[bytes_disassembled], size, address, bytes_disassembled, count - j);
        }
    }
    else
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}

void process_inspect(int pid, struct user_regs_struct *regs, breakpoint_t *breakpoint)
{
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs->rip, 0);
    if (current_ins == -1)
        die("(peekdata) %s", strerror(errno));
    fprintf(stderr, "Breakpoint \x1b[34m0x%lx\x1b[0m", breakpoint->address);
    if (breakpoint->symbol != NULL)
        fprintf(stderr, " in \x1b[33m%s\x1b[0m", breakpoint->symbol);
    fprintf(stderr, "\n");
    unsigned char *buffer = NULL;
    size_t bytes_read = get_instruction_buffer(&buffer, pid, breakpoint->address, 11);
    disas(handle, (unsigned char *)buffer, bytes_read, breakpoint->address, 0, 11);
}

void set_breakpoint(int pid, long addr, const char *symbol)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (previous_code == -1)
        die("(peekdata) %s", strerror(errno));
    // If symbol not given, try and find it
    symbol = (symbol != NULL) ? symbol : get_symbol(addr);
    int index = add_breakpoint(breakpoints, addr, previous_code, symbol);
    if (index >= 0)
    {
        fprintf(stderr, "Breakpoint %d at \x1b[34m0x%lx\x1b[0m", index, addr);
        if (symbol != NULL)
            fprintf(stderr, " \x1b[33m<%s>\x1b[0m", symbol);
        fprintf(stderr, "\n");
        /* Insert the breakpoint. */
        long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
        if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
            die("(pokedata) %s", strerror(errno));
    }
}
void reset_breakpoint(int pid, breakpoint_t *breakpoint)
{
    long trap = (breakpoint->previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));
}
int set_symbol_breakpoint(int pid, const char *symbol)
{
    long addr = get_symbol_value(symbol);
    if (addr == -1)
        return -1;
    set_breakpoint(pid, addr, symbol);
    return 0;
}

breakpoint_t *serve_breakpoint(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    breakpoint_t *breakpoint = get_breakpoint_by_address(breakpoints, regs.rip - 1);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)breakpoint->previous_code) == -1)
        die("(pokedata) %s", strerror(errno));
    regs.rip = breakpoint->address;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));
    process_inspect(pid, &regs, breakpoint);
    return breakpoint;
}

void delete_breakpoint(pid_t pid, int index)
{
    breakpoint_t *breakpoint = get_breakpoint(breakpoints, index);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)breakpoint->previous_code) == -1)
        die("(pokedata) %s", strerror(errno));
    remove_breakpoint(breakpoints, index);
}
void clear_breakpopints(pid_t pid)
{
    int total = get_num_breakpoints(breakpoints);
    for (int i = 0; i < total; i++)
        delete_breakpoint(pid, i);
}

int check_if_breakpoint(pid_t pid, struct user_regs_struct *regs)
{
    // Get opcode of previous instruction(the one that caused pause)
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs->rip - 1, 0);
    if (current_ins == -1)
        die("(peekdata) %s", strerror(errno));
    current_ins &= 0x00000000000000FF;

    return current_ins == 0xcc;
}
int process_step(int pid, int steps)
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
            // Replace breakpoint with actual code, execute it and reset the breakpoint
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
            if (errno == ESRCH)
            {
                /* System call was exit; so we need to end.  */
                fprintf(stderr, "\n");
                return CHILD_EXIT;
            }
            die("%s", strerror(errno));
        }
    }
    unsigned char *buffer = NULL;
    size_t bytes_read = get_instruction_buffer(&buffer, pid, regs.rip, 11);
    disas(handle, (unsigned char *)buffer, bytes_read, regs.rip, 0, 11);
    return 0;
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
int continue_execution(pid_t pid)
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
    // Execute instruction execution paused on
    if (regs.rip == last_hit_breakpoint->address)
    {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
            die("(singlestep) %s", strerror(errno));
        waitpid(pid, 0, 0);
    }

    // Reset breakpoint at that address
    reset_breakpoint(pid, last_hit_breakpoint);
    int status = 0;
    while (1)
    {
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
            die("%s", strerror(errno));
        /* Block until process state change (i.e., next event). */
        if (waitpid(pid, &status, 0) == -1)
            die("%s", strerror(errno));

        /* Collect information about the system call.  */
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

pid_t reload_child(pid_t child_pid, char **argv)
{
    kill(child_pid, SIGKILL);
    waitpid(child_pid, NULL, 0);
    pid_t pid = load_child(argv);
    for (int i = 0; i < breakpoints->size; i++)
        reset_breakpoint(pid, get_breakpoint(breakpoints, i));
    return pid;
}

char *get_command()
{
    char *input = malloc(60 * sizeof(char));
    if (fgets(input, 60 * sizeof(char), stdin) == NULL)
    {
        printf("Error reading input.\n");
        return NULL;
    }
    size_t len = strlen(input);
    if (len > 1 && input[len - 1] == '\n')
    {
        input[len - 1] = '\0';
        return input;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("my_gdb <program>: %d", argc);
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    if (initialize_elf_engine(argv[1]) == -1)
        die("(elf initialize) %s", elf_errmsg(-1));

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    pid_t pid = load_child(argv);

    breakpoints = list_init();
    char *command = NULL;
    while (1)
    {
        printf("(paphitisdb) ");
        command = get_command(command);
        if (command == NULL)
        {
            fprintf(stderr, "Enter command\n");
            continue;
        }
        char *token = strtok(command, " ");
        if (!strcmp(token, "r"))
        {
            if (child_state == EXECUTING)
                pid = reload_child(pid, argv);
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
                token = strtok(NULL, " ");
                int steps = token == NULL ? 1 : atoi(token);
                if (process_step(pid, steps) == CHILD_EXIT)
                {
                    child_state = EXITED;
                    break;
                }
            }
        }
        else if (!strcmp(token, "b"))
        {
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
                    printf("Symbol not found\n");
            }
        }
        else if (!strcmp(token, "l"))
            print_list(breakpoints);
        else if (!strcmp(token, "d"))
        {
            token = strtok(NULL, " "); // Get the next token
            if (token == NULL)
                clear_breakpopints(pid);
            else
            {
                int index = (int)strtol(token, NULL, 10);
                delete_breakpoint(pid, index);
            }
        }
        else if (!strcmp(token, "quit"))
            break;
        else if (!strcmp(token, "clear"))
        {
            fprintf(stderr, "\033[H\033[J");
            fflush(stderr);
        }
        else
        {
            printf(
                "Commands:\n"
                "b *<address>/<symbol>\tSets breakpoint\n"
                "l\t\t\tPrints list of set breakpoints\n"
                "r\t\t\tChild (re)starts execution\n"
                "c\t\t\tChild continues execution\n"
                "si <steps>\t\tSingle steps <steps> instruction, 1 if omitted\n"
                "d [index]\t\tDelete breakpoint at index, if not defined deletes all\n"
                "quit\t\t\tExits\n"
                "clear\t\t\tClears screen\n");
        }
        free(command);
    }
    list_destroy(breakpoints);
    cs_close(&handle);
}