/* Synchronous bounded byte writer (CSV or binary). SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MEMTRACE_WRITER_H
#define MEMTRACE_WRITER_H
#include <errno.h>
#include <fcntl.h>
#include <lzma.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TRACE_BUFFER_SIZE (64 * 1024)
typedef struct TraceWriter {
    FILE *file;
    const char *path;
    const char *name;
    bool xz, active, failed;
    unsigned int level;
    lzma_stream codec;
    unsigned char input[TRACE_BUFFER_SIZE], output[TRACE_BUFFER_SIZE];
    char stdio_buffer[TRACE_BUFFER_SIZE];
    size_t used;
} TraceWriter;

static bool writer_error(TraceWriter *w, const char *operation)
{
    if (!w->failed) {
        fprintf(stderr, "memtrace: %s %s failed for '%s': %s; capture incomplete\n",
                w->name, operation, w->path, strerror(errno ? errno : EIO));
    }
    w->failed = true;
    return false;
}

/* Exclusive creation also rejects symlinks, existing hard links and devices.
 * No existing input or output is ever truncated, including QEMU's -D file.
 */
static FILE *trace_create(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE *f;
    if (fd < 0) {
        return NULL;
    }
    f = fdopen(fd, "wb");
    if (!f) {
        int error = errno;
        close(fd);
        errno = error;
    }
    return f;
}

static bool writer_open(TraceWriter *w, const char *name, const char *path,
                        bool xz, unsigned int level)
{
    w->name = name;
    w->path = path;
    w->xz = xz;
    w->level = level;
    w->codec = (lzma_stream)LZMA_STREAM_INIT;
    w->file = trace_create(path);
    if (!w->file) {
        return writer_error(w, "open");
    }
    errno = 0;
    if (setvbuf(w->file, w->stdio_buffer, _IOFBF, sizeof(w->stdio_buffer))) {
        return writer_error(w, "buffer configuration");
    }
    return true;
}

static bool writer_encode(TraceWriter *w, lzma_action action)
{
    lzma_ret result;
    if (!w->active) {
        result = lzma_easy_encoder(&w->codec, w->level, LZMA_CHECK_CRC64);
        if (result != LZMA_OK) {
            fprintf(stderr, "memtrace: %s encoder initialization code=%u\n",
                    w->name, (unsigned int)result);
            errno = EIO;
            return writer_error(w, "compression initialization");
        }
        w->active = true;
    }
    w->codec.next_in = w->input;
    w->codec.avail_in = w->used;
    do {
        w->codec.next_out = w->output;
        w->codec.avail_out = sizeof(w->output);
        result = lzma_code(&w->codec, action);
        if (result != LZMA_OK && result != LZMA_STREAM_END) {
            fprintf(stderr, "memtrace: %s compression code=%u\n",
                    w->name, (unsigned int)result);
            errno = EIO;
            return writer_error(w, "compression");
        }
        size_t n = sizeof(w->output) - w->codec.avail_out;
        errno = 0;
        if (n && fwrite(w->output, 1, n, w->file) != n) {
            return writer_error(w, "write");
        }
    } while (w->codec.avail_in || !w->codec.avail_out ||
             (action == LZMA_FINISH && result != LZMA_STREAM_END));
    w->used = 0;
    if (result == LZMA_STREAM_END) {
        lzma_end(&w->codec);
        w->codec = (lzma_stream)LZMA_STREAM_INIT;
        w->active = false;
    }
    return true;
}

static bool writer_write(TraceWriter *w, const char *data, size_t size)
{
    if (w->failed) {
        return false;
    }
    if (!w->xz) {
        errno = 0;
        return fwrite(data, 1, size, w->file) == size || writer_error(w, "write");
    }
    while (size) {
        size_t n = sizeof(w->input) - w->used;
        if (n > size) {
            n = size;
        }
        memcpy(w->input + w->used, data, n);
        w->used += n;
        data += n;
        size -= n;
        if (w->used == sizeof(w->input) && !writer_encode(w, LZMA_RUN)) {
            return false;
        }
    }
    return true;
}

/* Finalize the current XZ segment for concatenated-stream boundary visibility.
 * The caller supplies one logical header and, for binary, one final footer.
 * No unbounded pending queue; a boundary with no pending bytes adds no stream.
 * fflush gives codec/stdio completion, NOT fsync durability.
 */
static bool writer_boundary(TraceWriter *w)
{
    if (!w->file) {
        return true;
    }
    if (w->failed) {
        return false;
    }
    if (w->xz && (w->used || w->active) && !writer_encode(w, LZMA_FINISH)) {
        return false;
    }
    errno = 0;
    return !fflush(w->file) || writer_error(w, "flush");
}

static bool writer_close(TraceWriter *w)
{
    bool ok = !w->failed;
    if (w->file) {
        if (!w->failed) {
            ok = writer_boundary(w);
        }
        lzma_end(&w->codec);
        errno = 0;
        if (fclose(w->file)) {
            ok = writer_error(w, "close");
        }
        w->file = NULL;
    }
    return ok;
}
#endif
