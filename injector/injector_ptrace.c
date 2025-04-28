#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#ifndef PTRACE_GETREGS
  #define PTRACE_GETREGS 12
#endif

#ifndef PTRACE_SETREGS
  #define PTRACE_SETREGS 13
#endif

#define TERM_WIDTH 167
#define PROT_RWX PROT_READ | PROT_WRITE | PROT_EXEC
#define MAP_ANONP MAP_ANONYMOUS | MAP_PRIVATE

struct syscall_args {
    uint64_t rax, rdi, rsi, rdx, r10, r8, r9;
};

void dump_regs(struct user_regs_struct* regs);

int attach_to_pid(pid_t target_pid) {
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        fprintf(stderr, "-> errno: %d\n", errno);
        return -1;
    }

    waitpid(target_pid, NULL, 0);
    return 0;
}

uintptr_t get_module_base(pid_t pid, const char* module_name, bool only_high_addr) {
    char path[64], line[512];
    FILE* handle;
    uintptr_t addr = 0;

    if (pid <= 0) snprintf(path, sizeof(path), "/proc/self/maps");
    else snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    handle = fopen(path, "r");
    if (!handle) {
        perror("fopen");
        fprintf(stderr, "get_module_base: failed to get a file handle at %s\n", path);
        return 0;
    }

    printf("get_module_base: parsing file \"%s\"...\n", path);
    while (fgets(line, sizeof(line), handle)) {
        if (strstr(line, module_name)) {
            printf("get_module_base: scanning line: %s", line);
            addr = strtoul(line, NULL, 16);
            if (only_high_addr && addr < 0x700000000000) {
                addr = 0;
                continue;
            }
            break;
        }
    }

    if (addr == 0) printf("get_module_base: module base of \"%s\"%s not found...\n", module_name, (only_high_addr ? "(high)" : ""));
    else printf("get_module_base: found module base of \"%s\"%s at addr %#" PRIxPTR "\n", module_name, (only_high_addr ? " (high)" : ""), addr);

    fclose(handle);
    return addr;
}

size_t get_module_size(pid_t pid, const char* module_name, bool only_high_addr) {
    char path[64], line[512];
    FILE* handle;
    size_t start = 0, end = 0, size;

    if (pid <= 0) snprintf(path, sizeof(path), "/proc/self/maps");
    else snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    handle = fopen(path, "r");
    if (!handle) {
        perror("fopen");
        fprintf(stderr, "get_module_size: failed to get a file handle at %s\n", path);
        return -1;
    }

    printf("get_module_size: parsing file \"%s\"...\n", path);
    while (fgets(line, sizeof(line), handle)) {
        if (strstr(line, module_name)) {
            printf("get_module_size: scanning line: %s", line);
            size_t tmp_start, tmp_end;
            sscanf(line, "%lx-%lx", &tmp_start, &tmp_end);

            if (only_high_addr && tmp_start < 0x700000000000) continue;
            if (start == 0) start = tmp_start;
            end = tmp_end;
        }
    }

    size = end > start ? end - start : 0;

    if (size == 0) printf("get_module_base: cannot calculate size of \"%s\"%s...\n", module_name, (only_high_addr ? "(high)" : ""));
    else printf("get_module_size: calculated size for \"%s\"%s: 0x%lx\n", module_name, only_high_addr ? " (high)" : "", size);

    fclose(handle);
    return size;
}

const char* find_addr_region(pid_t pid, void* remote_addr) {
    char path[64], line[512], region_name[128];
    FILE* handle;
    uintptr_t addr = (uintptr_t)remote_addr;
    size_t start = 0, end = 0;

    if (pid <= 0) snprintf(path, sizeof(path), "/proc/self/maps");
    else snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    handle = fopen(path, "r");
    if (!handle) {
        perror("fopen");
        fprintf(stderr, "find_addr_region: failed to get a file handle at %s\n", path);
        return NULL;
    }

    while (fgets(line, sizeof(line), handle)) {
        size_t tmp_start, tmp_end;
        sscanf(line, "%lx-%lx", &tmp_start, &tmp_end);
        if (start == 0) start = tmp_start;
        end = tmp_end;

        if (start < addr && end > addr) {
            const char* p = line;
            int spaces = 0;

            while (*p) {
                if (*p == ' ') ++spaces;
                else {
                    if (spaces > 1) break;
                    spaces = 0;
                }
                ++p;
            }

            strncpy(region_name, p, sizeof(region_name) - 1);
            char* slash_n = strchr(region_name, '\n');
            if (slash_n) *(slash_n) = '\0';
            break;
        }
    }

    fclose(handle);
    return strdup(region_name);
}

ssize_t read_remote_memory(pid_t pid, void* remote_addr, void* buffer, size_t size) {
    struct iovec local_iov = {buffer, size};
    struct iovec remote_iov = {remote_addr, size};

    ssize_t ret = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (ret == -1) {
        perror("process_vm_writev");
        fprintf(stderr, "-> errno: %d\n", errno);
    } else printf("read_remote_memory: success, read %zd (0x%zx) bytes at 0x%zx\n", size, size, (uintptr_t)remote_addr);

    return ret;
}

ssize_t write_remote_memory(pid_t pid, void* remote_addr, void* buffer, size_t size) {
    struct iovec local_iov = {buffer, size};
    struct iovec remote_iov = {remote_addr, size};

    ssize_t ret = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (ret == -1) {
        perror("process_vm_writev");
        fprintf(stderr, "-> errno: %d\n", errno);
    } else printf("write_remote_memory: success, wrote %zd bytes (0x%zx) at 0x%zx\n", size, size, (uintptr_t)remote_addr);

    return ret;
}

void* find_syscall_gadget(pid_t pid) {
    uintptr_t module_base = get_module_base(pid, "bionic/libc.so", false);
    size_t module_size = get_module_size(pid, "bionic/libc.so", false);
    uintptr_t syscall_gadget = 0;

    uint8_t* buffer = malloc(module_size);
    if (!buffer) {
        perror("malloc");
        return NULL;
    }

    if (read_remote_memory(pid, (void* )module_base, buffer, module_size) < 0) {
        perror("process_vm_readv");
        free(buffer);
        return NULL;
    }

    for (size_t i = 0; i < module_size - 9; i++) {
        uint8_t p[10] = {
            buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3],
            buffer[i + 4], buffer[i + 5], buffer[i + 6], buffer[i + 7],
            buffer[i + 8], buffer[i + 9]
        };

        if (p[0] == 0x0f && p[1] == 0x05 && p[2] == 0xcc) {
            printf("find_syscall_gadget: syscall opcode found at +0x%zx: %02x %02x %02x\n", i, p[0], p[1], p[2]);
            syscall_gadget = module_base + i;
            break;
        }
    }

    if (syscall_gadget != 0)
        printf("find_syscall_gadget: calculated remote_syscall addr: %#" PRIxPTR ", located at %s\n", syscall_gadget, find_addr_region(pid, (void* )syscall_gadget));
    else fprintf(stderr, "find_syscall_gadget: no syscall opcode found\n");

    free(buffer);
    return (void*)syscall_gadget;
}

int ptrace_getregs(pid_t pid, struct user_regs_struct* regs, bool silent) {
    int ret = ptrace(PTRACE_GETREGS, pid, NULL, regs);
    if (ret == -1) {

        perror("ptrace(PTRACE_GETREGS)");
        fprintf(stderr, "-> errno: %d\n", errno);
        return -1;
    }

    if (!silent) {
        printf("ptrace_getregs: ptrace(PTRACE_GETREGS) success, obtained regs:\n");
        dump_regs(regs);
    }

    return ret;
}

int ptrace_setregs(pid_t pid, struct user_regs_struct* regs, bool silent) {
    int ret = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if (ret == -1) {
        perror("ptrace(PTRACE_SETREGS)");
        fprintf(stderr, "-> errno: %d\n", errno);
        return -1;
    }

    if (!silent) {
        printf("ptrace_setregs: ptrace(PTRACE_SETREGS) success, set regs:\n");
        dump_regs(regs);
    }

    return ret;
}

int ptrace_cont(pid_t pid) {
    int ret = ptrace(PTRACE_CONT, pid, 0, 0);
    if (ret == -1) {
        perror("ptrace(PTRACE_CONT)");
        fprintf(stderr, "-> errno: %d\n", errno);
        return -1;
    }

    printf("ptrace_cont: ptrace(PTRACE_CONT) success\n");
    return ret;
}

int ptrace_kill(pid_t pid) {
    int ret = ptrace(PTRACE_KILL, pid, 0, 0);
    if (ret == -1) {
        perror("ptrace(PTRACE_KILL)");
        fprintf(stderr, "-> errno: %d\n", errno);
        return -1;
    }

    printf("ptrace_kill: ptrace(PTRACE_KILL) success: killed process %d\n", pid);
    return ret;
}

uint64_t issue_syscall(pid_t pid, struct user_regs_struct* regs, struct user_regs_struct* orig, void* syscall_gadget, struct syscall_args args) {
    ptrace_getregs(pid, regs, true);
    orig = regs;

    regs->rax = args.rax;
    regs->rdi = args.rdi;
    regs->rsi = args.rsi;
    regs->rdx = args.rdx;
    regs->r10 = args.r10;
    regs->r8 = args.r8;
    regs->r9 = args.r9;
    regs->rip = (uintptr_t)syscall_gadget;

    printf("issue_syscall: issuing syscall #%ld to remote with regs:\n", regs->rax);
    dump_regs(regs);
    ptrace_setregs(pid, regs, true);
    ptrace_cont(pid);
    waitpid(pid, NULL, 0);

    ptrace_getregs(pid, regs, true);
    uint64_t ret = regs->rax;
    printf("issue_syscall: syscall returned: %ld (0x%lx)\n", ret, ret);
    ptrace_setregs(pid, orig, true);
    ptrace_cont(pid);
    waitpid(pid, NULL, 0);

    return ret;
}

void dump_regs(struct user_regs_struct* regs) {
    printf("RIP: 0x%016lx  RSP: 0x%016lx  RBP: 0x%016lx\n", regs->rip, regs->rsp, regs->rbp);
    printf("RAX: 0x%016lx  RBX: 0x%016lx  RCX: 0x%016lx  RDX: 0x%016lx\n", regs->rax, regs->rbx, regs->rcx, regs->rdx);
    printf("RSI: 0x%016lx  RDI: 0x%016lx  R8 : 0x%016lx  R9 : 0x%016lx\n", regs->rsi, regs->rdi, regs->r8, regs->r9);
    printf("R10: 0x%016lx  R11: 0x%016lx  R12: 0x%016lx  R13: 0x%016lx\n", regs->r10, regs->r11, regs->r12, regs->r13);
    printf("R14: 0x%016lx  R15: 0x%016lx  EFLAGS: 0x%016lx\n", regs->r14, regs->r15, regs->eflags);
}

bool dump_memory_maps(pid_t pid, const char* filter) {
    char path[64], line[512];
    FILE* handle;

    if (pid <= 0) snprintf(path, sizeof(path), "/proc/self/maps");
    else snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    handle = fopen(path, "r");
    if (!handle) {
        perror("fopen");
        fprintf(stderr, "dump_memory_maps: failed to get a file handle at %s\n", path);
        return false;
    }

    bool ret = false;
    printf("dump_memory_maps: %s with filter \"%s\":\n", path, filter == NULL ? "<NONE>" : filter);
    while (fgets(line, sizeof(line), handle)) {
        if (filter == NULL || strstr(line, filter)) {
            printf("-> %s", line);
            ret = true;
        }
    }

    fclose(handle);
    return ret;
}

bool dump_thread_memory_maps(pid_t pid, pid_t tid, const char* filter) {
    char path[64], line[512];
    FILE* handle;

    if (pid <= 0) snprintf(path, sizeof(path), "/proc/self/task/%d/maps", tid);
    else snprintf(path, sizeof(path), "/proc/%d/task/%d/maps", pid, tid);

    handle = fopen(path, "r");
    if (!handle) {
        perror("fopen");
        fprintf(stderr, "dump_thread_memory_maps: failed to get a file handle at %s\n", path);
        return false;
    }

    bool ret = false;
    printf("dump_thread_memory_maps: %s with filter \"%s\":\n", path, filter);
    while (fgets(line, sizeof(line), handle)) {
        if (filter == NULL || strstr(line, filter)) {
            printf("-> %s", line);
            ret = true;
        }
    }

    fclose(handle);
    return ret;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 1;
    }

    clock_t start = clock();
    pid_t target_pid = atoi(argv[1]);
    printf("main: target_pid: %d\n", target_pid);

    if (attach_to_pid(target_pid) == -1) return -1;
    printf("main: attached to process %d\n", target_pid);

    void* syscall_gadget = find_syscall_gadget(target_pid);
    struct user_regs_struct regs, orig;

    issue_syscall(target_pid, &regs, &orig, syscall_gadget, (struct syscall_args) {
        .rax=9, .rdi=0, .rsi=0x11307, .rdx=PROT_RWX, .r10=MAP_ANONP, .r8=-1, .r9=0
    });

    double timestamp = 1000 * (double)((clock() - start)) / CLOCKS_PER_SEC < 30000;
    while (timestamp < 30000) {
        printf("main: timestamp: %.2fms, waiting for 30000ms\n", timestamp);
    }

    dump_memory_maps(target_pid, "libil2cpp.so");
}
