#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    pid_t pid = atoi(argv[1]);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH failed");
        return 1;
    }

    waitpid(pid, NULL, 0);
    printf("attached. sending CONT...\n");

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("PTRACE_CONT failed");
        return 1;
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

