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

#define TOOL "min_gdb"

#define die(...) \
    do { \
        fprintf(stderr, TOOL": " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)


#define BREAKPOINT_ADDR 0x0000000000401159

void process_inspect(int pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
            die("%s", strerror(errno));
  
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
    if (current_ins == -1) 
        die("(peekdata) %s", strerror(errno));
   
    fprintf(stderr, "=> 0x%llx: 0x%lx\n", regs.rip, current_ins);
 
}

long set_breakpoint(int pid, long addr) {
    /* Backup current code.  */
    long previous_code = 0; 
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)BREAKPOINT_ADDR, 0);
    if (previous_code == -1)
        die("(peekdata) %s", strerror(errno));

    fprintf(stderr, "0x%p: 0x%lx\n", (void *)BREAKPOINT_ADDR, previous_code);

    /* Insert the breakpoint. */
    long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)BREAKPOINT_ADDR, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));
  
    /* Resume process.  */ 
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
        die("(cont) %s", strerror(errno));
   
    return previous_code; 
}

void process_step(int pid) {

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));
 
    waitpid(pid, 0, 0);
}

void serve_breakpoint(int pid, long original_instruction) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
            die("(getregs) %s", strerror(errno));
  
    process_inspect(pid); 
    getchar();

    fprintf(stderr, "Resuming.\n");

    if (ptrace(PTRACE_POKEDATA, pid, (void *)BREAKPOINT_ADDR, (void *)original_instruction)  == -1)
        die("(pokedata) %s", strerror(errno));
    
    regs.rip = BREAKPOINT_ADDR;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));

}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("min_strace <program>: %d", argc);

    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            die("%s", strerror(errno));
        case 0:  /* Code that is run by the child. */
            /* Start tracing.  */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* execvp() is a system call, the child will block and
               the parent must do waitpid().
               The waitpid() of the parent is in the label
               waitpid_for_execvp.
             */
            execvp(argv[1], argv + 1);
            die("%s", strerror(errno));
    }

    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    waitpid(pid, 0, 0);

    long original_instruction = set_breakpoint(pid, BREAKPOINT_ADDR);

    waitpid(pid, 0, 0);

    /* We are in the breakpoint.  */
    serve_breakpoint(pid, original_instruction);

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
       die("(cont) %s", strerror(errno));

    waitpid(pid, 0, 0);
}
