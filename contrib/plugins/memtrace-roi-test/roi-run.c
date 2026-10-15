/* Whole-command global ROI wrapper. SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "roi-run requires x86-64 Linux"
#endif
#define BEGIN() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47" ::: "memory")
#define END() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e" ::: "memory")

int main(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[1], "--") || !argv[2][0]) {
        fprintf(stderr, "usage: %s -- COMMAND ARG...\n", argv[0]);
        return 2;
    }
    if (printf("roi-run: starting command=%s\n", argv[2]) < 0 || fflush(NULL)) {
        perror("roi-run: output before BEGIN");
        return 125;
    }

    /* One BEGIN in the parent before fork; only the parent emits END.
     * Child launch, loading, execution, teardown and guest kernel work belong
     * to the global interval. Do not wrap a program with its own ROI markers.
     * No END can be promised if this parent is killed or cannot keep running.
     */
    BEGIN();
    pid_t child = fork();
    if (child < 0) {
        int error = errno;
        END();
        fprintf(stderr, "roi-run: fork failed: %s\n", strerror(error));
        return 125;
    }
    if (child == 0) {
        execvp(argv[2], &argv[2]);
        int error = errno;
        /* Exceptional failure diagnostics are permitted within the ROI.
         * _exit avoids flushing copied parent buffers or running handlers.
         * Arguments are passed unchanged; no shell is inserted by the wrapper.
         */
        fprintf(stderr, "roi-run: execvp(%s) failed: %s\n", argv[2], strerror(error));
        _exit(error == ENOENT || error == ENOTDIR ? 127 : 126);
    }

    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    int error = errno;
    END();
    if (waited < 0) {
        fprintf(stderr, "roi-run: waitpid failed: %s; child outcome unavailable\n",
                strerror(error));
        return 125;
    }
    if (waited != child) {
        fprintf(stderr, "roi-run: unexpected waitpid result; child outcome unavailable\n");
        return 125;
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        printf("roi-run: child exited with status=%d\n", code);
        return code;
    }
    if (WIFSIGNALED(status)) {
        int signal = WTERMSIG(status);
        printf("roi-run: child terminated by signal=%d; wrapper status=%d\n",
               signal, 128 + signal);
        return 128 + signal;
    }
    fprintf(stderr, "roi-run: unexpected child status; outcome unavailable\n");
    return 125;
}
