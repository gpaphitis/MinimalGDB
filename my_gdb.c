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

#define CHILD_BREAKPOINT 0
#define CHILD_EXIT 1
#define MAX_INSN_SIZE 15

list_t *breakpoints;
csh handle;
Elf *elf;

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

void print_ins(cs_insn *ins)
{

    fprintf(stderr, "0x%016lx:\t%s\t\t%s\n", ins->address, ins->mnemonic, ins->op_str);
}

void disas(csh handle, const unsigned char *buffer, unsigned int size, breakpoint_t *breakpoint)
{
    cs_insn *insn;
    size_t count;

    count = cs_disasm(handle, buffer, size, 0x0, 11, &insn);

    if (count > 0)
    {
        size_t j;
        for (j = 0; j < count; j++)
        {
            if (j == 0)
                fprintf(stderr, "=>");
            fprintf(stderr, "0x%" PRIx64 ":\t%s\t\t%s\n", breakpoint->address + insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);
        }
        cs_free(insn, count);
    }
    else
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}

void process_inspect(int pid, struct user_regs_struct *regs, breakpoint_t *breakpoint)
{
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs->rip, 0);
    if (current_ins == -1)
        die("(peekdata) %s", strerror(errno));
    // fprintf(stderr, "=> 0x%llx: 0x%lx\n", regs->rip, current_ins);
    unsigned char *buffer = malloc(MAX_INSN_SIZE * 11);
    size_t bytes_read = 0;
    while (bytes_read < MAX_INSN_SIZE * 11)
    {
        // Read a word (sizeof(long)) from the child process memory
        long word = ptrace(PTRACE_PEEKDATA, pid, breakpoint->address + bytes_read, NULL);
        if (word == -1 && errno != 0)
        {
            free(buffer);
            die("(peekdata) %s", strerror(errno));
        }

        // Copy the word to the buffer byte-by-byte
        for (size_t i = 0; i < sizeof(word) && bytes_read + i < MAX_INSN_SIZE * 11; i++)
        {
            buffer[bytes_read + i] = (word >> (i * 8)) & 0xFF;
        }

        bytes_read += sizeof(word);
    }
    disas(handle, (const unsigned char *)buffer, bytes_read, breakpoint);
}

long set_breakpoint(int pid, long addr)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (previous_code == -1)
        die("(peekdata) %s", strerror(errno));
    add_breakpoint(breakpoints, addr, previous_code);

    fprintf(stderr, "0x%p: 0x%lx\n", (void *)addr, previous_code);

    /* Insert the breakpoint. */
    long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));

    return previous_code;
}

void process_step(int pid)
{

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);
}

void serve_breakpoint(int pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    fprintf(stderr, "Resuming.\n");

    breakpoint_t *breakpoint = get_breakpoint_by_address(breakpoints, regs.rip - 1);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)breakpoint->address, (void *)breakpoint->previous_code) == -1)
        die("(pokedata) %s", strerror(errno));
    regs.rip = breakpoint->address;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));
    process_inspect(pid, &regs, breakpoint);
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
            serve_breakpoint(pid);
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
            execute(pid);
        else if (!strcmp(token, "c"))
            execute(pid);
        else if (!strcmp(token, "b"))
        {
            token = strtok(NULL, " "); // Get the next token
            printf("token: %s\n", token);
            long address = (long)strtol(token, NULL, 16);
            set_breakpoint(pid, address);
        }
        else if (!strcmp(token, "p"))
            print_list(breakpoints);
        else if (!strcmp(token, "del"))
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
        else
        {
            printf(
                "Commands:\n"
                "b <address>\tSets breakpoint\n"
                "p\t\t\tPrints list of set breakpoints\n"
                "r\t\t\tChild (re)starts execution\n"
                "c\t\t\tChild continues execution\n"
                "del [index]\tDelete breakpoint at index, if not defined deletes all\n");
        }
        free(command);
    }
    list_destroy(breakpoints);
    cs_close(&handle);
}
