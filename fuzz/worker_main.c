/*
 * Persistent fuzz worker.
 *
 * Protocol over stdin/stdout (length-prefixed, fully synchronous):
 *   parent -> worker : uint32_le n, followed by n bytes of fuzzer input
 *   worker -> parent : uint32_le 1 + 1 byte result code
 *                       0 = decoder returned cleanly (any SPNG error)
 *                       1 = internal harness sanity failure
 *
 * The worker never exits on a normal decode result: the parent reuses the
 * process across inputs. On a memory error / UB / assertion the sanitizer
 * runtime aborts the process (pipe EOF / signal observed by the parent),
 * which is how crashes are detected. The parent then spawns a fresh worker.
 *
 * stderr is inherited so ASan/UBSan reports land in a per-worker log file
 * the parent redirects to.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int read_full(uint8_t *buf, size_t n)
{
    size_t off = 0;
    while(off < n)
    {
        ssize_t r = read(STDIN_FILENO, buf + off, n - off);
        if(r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int write_full(const uint8_t *buf, size_t n)
{
    size_t off = 0;
    while(off < n)
    {
        ssize_t w = write(STDOUT_FILENO, buf + off, n - off);
        if(w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

int main(void)
{
    uint8_t hdr[4];

    for(;;)
    {
        if(read_full(hdr, 4)) return 0; /* parent closed pipe */

        uint32_t n = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                     ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);

        if(n == 0 || n > (64u * 1024u * 1024u))
        { /* protocol violation / absurd input: refuse without touching memory */
            uint8_t reply[5] = { 1, 0, 0, 0, 1 };
            if(write_full(reply, 5)) return 0;
            continue;
        }

        uint8_t *buf = (uint8_t*)malloc(n);
        if(buf == NULL) return 2;

        if(read_full(buf, n))
        {
            free(buf);
            return 0;
        }

        int rc = LLVMFuzzerTestOneInput(buf, (size_t)n);
        free(buf);

        uint8_t reply[5] = { 1, 0, 0, 0, (uint8_t)(rc != 0) };
        if(write_full(reply, 5)) return 0;
    }
}
