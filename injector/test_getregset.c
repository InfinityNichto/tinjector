#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/elf.h>

struct user_pt_regs_stub {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

int main() {
    pid_t pid = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    struct user_pt_regs_stub regs;
    struct iovec io = {
        .iov_base = &regs,
        .iov_len = sizeof(regs)
    };

    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io) == -1) {
        perror("ptrace(GETREGSET)");
        printf("iov_len: %lu\n", io.iov_len);
        return 1;
    }

    printf("PC: 0x%lx\n", regs.pc);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
