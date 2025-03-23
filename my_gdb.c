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

#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

/* Custom */
#include "breakpoints.h"

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
Elf *elf;

enum child_state_t
{
    LOADED,
    EXECUTING,
    EXITED
} child_state;

Elf_Data *find_text(long unsigned *text_start, long unsigned *text_end)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    Elf_Data *data = NULL;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));

        /* Locate .text  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".text"))
        {
            data = elf_getdata(scn, data);
            if (!data)
                die("(getdata) %s", elf_errmsg(-1));

            *text_start = shdr.sh_addr;
            *text_end = *text_start + shdr.sh_size;

            return (data);
        }
    }
    return NULL;
}
char *get_symbol(long address)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    Elf_Data *data;
    int count = 0;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));
        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
        {
            data = elf_getdata(scn, NULL);
            count = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < count; ++i)
            {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                if (address == sym.st_value)
                    return elf_strptr(elf, shdr.sh_link, sym.st_name);
            }
        }
    }
    return NULL;
}
long get_symbol_value(const char *symbol)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    Elf_Data *data;
    int count = 0;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));
        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
        {
            data = elf_getdata(scn, NULL);
            count = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < count; ++i)
            {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                if (!strcmp(symbol, elf_strptr(elf, shdr.sh_link, sym.st_name)))
                    return sym.st_value;
            }
        }
    }
    return -1;
}

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
            fprintf(stderr, "%s\t\t%s\n", insn[j].mnemonic,
                    insn[j].op_str);
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
            disas(handle, &buffer[bytes_disassembled], size, address, bytes_disassembled, count - disassembled_count);
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
    for (int i = 0; i < steps; i++)
    {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
            die("(singlestep) %s", strerror(errno));

        waitpid(pid, 0, 0);
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
    // Execute instruction execution paused on
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));
    waitpid(pid, 0, 0);

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

char *get_command()
{
    char *input = malloc(60 * sizeof(char));
    if (fgets(input, 60 * sizeof(char), stdin) == NULL)
    {
        printf("Error reading input.\n");
        return NULL;
    }
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n')
    {
        input[len - 1] = '\0';
    }
    return input;
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("my_gdb <program>: %d", argc);
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    int fd = open(argv[1], O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        die("(begin) %s", elf_errmsg(-1));

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

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
    child_state = LOADED;

    // Wait for execvp()
    waitpid(pid, 0, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    breakpoints = list_init();
    char *command = NULL;
    while (1)
    {
        printf("(paphitisdb) ");
        command = get_command(command);
        char *token = strtok(command, " ");
        if (!strcmp(token, "r"))
        {
            if (child_state == LOADED)
            {
                child_state = EXECUTING;
                if (execute(pid) == CHILD_EXIT)
                    child_state = EXITED;
            }
            else
                printf("Program is executing or has finished\n");
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
        else
        {
            printf(
                "Commands:\n"
                "b *<address>/<symbol>\tSets breakpoint\n"
                "l\t\t\tPrints list of set breakpoints\n"
                "r\t\t\tChild (re)starts execution\n"
                "c\t\t\tChild continues execution\n"
                "d [index]\tDelete breakpoint at index, if not defined deletes all\n");
        }
        free(command);
    }
    list_destroy(breakpoints);
    cs_close(&handle);
}
