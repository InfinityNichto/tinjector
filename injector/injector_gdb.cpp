#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>

int main() {
    pid_t target_pid = atoi(argv[1]);
    const char* lib_path = argv[2];

    std::string cmd = "gdb -n -q -batch -ex 'attach " + std::to_string(target_pid) +
                      "' -ex 'call (void*)dlopen(\"" + lib_path + "\", 1)' -ex 'detach' -ex 'quit'";
    system(cmd.c_str());
}

