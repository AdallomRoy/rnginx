/*
 * mcount: LD_PRELOAD heap-allocation counter.
 *
 * Counts malloc/calloc/realloc/free and the aligned allocators, plus the
 * bytes requested, per process, and the blocks and usable bytes live right
 * now. The counters live in a shared mapping of /dev/shm/mcount.<pid>
 * (remapped in a forked child), so another process can read them while the
 * program runs:
 *
 *     struct { uint64_t malloc, calloc, realloc, free, memalign, bytes;
 *              int64_t live_blocks, live_bytes; }
 *
 * The real allocators are glibc's __libc_* entry points, so the counter
 * never recurses into itself.
 *
 * With MCOUNT_SAMPLE=N, every Nth allocation also records its call stack
 * (glibc backtrace(), which unwinds with .eh_frame) into
 * $MCOUNT_DIR/mcount-bt.<pid> (default /dev/shm): records of { uint32 nframes, uint32 size,
 * uint64 frames[nframes] } after a uint64 count of bytes used.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void  __libc_free(void *);
extern void *__libc_memalign(size_t, size_t);

struct counters {
    uint64_t malloc_n, calloc_n, realloc_n, free_n, memalign_n, bytes;
    int64_t  live_blocks, live_bytes;
};

static struct counters  dummy;
static struct counters *cnt = &dummy;

#define BT_SIZE   (256UL << 20)
#define BT_DEPTH  32

static uint64_t         sample_every;
static uint64_t         sample_tick;
static uint64_t        *bt;            /* bt[0]: bytes used after the header */
static __thread int     in_bt;

static void
map_counters(void)
{
    char  path[64];
    int   fd;
    void *p;

    snprintf(path, sizeof(path), "/dev/shm/mcount.%d", (int) getpid());

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }

    if (ftruncate(fd, sizeof(struct counters)) == 0) {
        p = mmap(NULL, sizeof(struct counters), PROT_READ | PROT_WRITE,
                 MAP_SHARED, fd, 0);
        if (p != MAP_FAILED) {
            memset(p, 0, sizeof(struct counters));
            cnt = p;
        }
    }

    close(fd);
}

static void
map_bt(void)
{
    char  path[256], *e;
    int   fd;
    void *p;

    bt = NULL;

    if (sample_every == 0) {
        return;
    }

    e = getenv("MCOUNT_DIR");
    snprintf(path, sizeof(path), "%s/mcount-bt.%d", e ? e : "/dev/shm", (int) getpid());

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }

    if (ftruncate(fd, BT_SIZE) == 0) {
        p = mmap(NULL, BT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p != MAP_FAILED) {
            bt = p;
        }
    }

    close(fd);
}

static void
child(void)
{
    cnt = &dummy;
    map_counters();
    map_bt();
}

static void
sample(size_t n)
{
    void     *frames[BT_DEPTH];
    int       k, i;
    uint64_t  off, need;
    uint32_t *hdr;

    if (bt == NULL || in_bt) {
        return;
    }

    if (__atomic_fetch_add(&sample_tick, 1, __ATOMIC_RELAXED) % sample_every) {
        return;
    }

    in_bt = 1;
    k = backtrace(frames, BT_DEPTH);
    in_bt = 0;

    if (k <= 0) {
        return;
    }

    need = 8 + 8 * (uint64_t) k;
    off = __atomic_fetch_add(&bt[0], need, __ATOMIC_RELAXED);

    if (8 + off + need > BT_SIZE) {
        return;
    }

    hdr = (uint32_t *) ((char *) bt + 8 + off);
    hdr[0] = (uint32_t) k;
    hdr[1] = (uint32_t) n;

    for (i = 0; i < k; i++) {
        ((uint64_t *) (hdr + 2))[i] = (uint64_t) (uintptr_t) frames[i];
    }
}

__attribute__((constructor)) static void
init(void)
{
    char *e = getenv("MCOUNT_SAMPLE");

    if (e) {
        sample_every = strtoull(e, NULL, 10);
    }

    if (sample_every) {
        /* backtrace() loads libgcc_s on first use, which allocates */
        void *f[2];
        in_bt = 1;
        backtrace(f, 2);
        in_bt = 0;
    }

    map_counters();
    map_bt();
    pthread_atfork(NULL, NULL, child);
}

#define ADD(f, v)  __atomic_fetch_add(&cnt->f, (v), __ATOMIC_RELAXED)

static void *
got(void *p)
{
    if (p) {
        ADD(live_blocks, 1);
        ADD(live_bytes, (int64_t) malloc_usable_size(p));
    }
    return p;
}

void *
malloc(size_t n)
{
    ADD(malloc_n, 1);
    ADD(bytes, n);
    sample(n);
    return got(__libc_malloc(n));
}

void *
calloc(size_t a, size_t b)
{
    ADD(calloc_n, 1);
    ADD(bytes, a * b);
    sample(a * b);
    return got(__libc_calloc(a, b));
}

void *
realloc(void *p, size_t n)
{
    void   *q;
    int64_t old;

    ADD(realloc_n, 1);
    ADD(bytes, n);
    sample(n);
    old = p ? (int64_t) malloc_usable_size(p) : 0;
    q = __libc_realloc(p, n);
    if (q) {
        ADD(live_bytes, (int64_t) malloc_usable_size(q) - old);
        if (p == NULL) {
            ADD(live_blocks, 1);
        }
    } else if (p && n == 0) {
        ADD(live_bytes, -old);
        ADD(live_blocks, -1);
    }
    return q;
}

void
free(void *p)
{
    if (p) {
        ADD(free_n, 1);
        ADD(live_blocks, -1);
        ADD(live_bytes, -(int64_t) malloc_usable_size(p));
    }
    __libc_free(p);
}

int
posix_memalign(void **pp, size_t align, size_t n)
{
    void *p;

    ADD(memalign_n, 1);
    ADD(bytes, n);
    sample(n);
    p = got(__libc_memalign(align, n));
    if (p == NULL) {
        return ENOMEM;
    }
    *pp = p;
    return 0;
}

void *
aligned_alloc(size_t align, size_t n)
{
    ADD(memalign_n, 1);
    ADD(bytes, n);
    sample(n);
    return got(__libc_memalign(align, n));
}

void *
memalign(size_t align, size_t n)
{
    ADD(memalign_n, 1);
    ADD(bytes, n);
    sample(n);
    return got(__libc_memalign(align, n));
}
