#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

int main() {
    pid_t pid = atoi(argv[1]);
    long val;

    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    errno = 0;
    val = ptrace(PTRACE_PEEKDATA, pid, (void*)0x400000, NULL);
    if (errno) perror("PEEKDATA");
    else printf("Value at 0x400000: %lx\n", val);

    long poke_test = 0xb16b00b5;
    if (ptrace(PTRACE_POKEDATA, pid, (void*)0x400000, (void*)poke_test) == -1)
        perror("POKEDATA");

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

