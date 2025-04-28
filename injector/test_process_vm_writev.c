#define _GNU_SOURCE
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    pid_t pid = atoi(argv[1]);
    char* msg = "hello-waydroid";
    size_t len = strlen(msg) + 1;

    struct iovec local = { .iov_base = msg, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)0x400000, .iov_len = len };

    ssize_t written = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (written == -1) perror("process_vm_writev");
    else printf("wrote %zd bytes\n", written);
}

