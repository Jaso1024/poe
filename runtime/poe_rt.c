#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>

#define POE_RT_MAGIC 0x504F4552
#define POE_RT_VERSION 1
#define POE_RT_DEFAULT_ENTRIES (1 << 16)
#define POE_RT_ENTRY_SIZE 32

typedef struct {
    uint64_t ts_ns;
    uint64_t func_addr;
    uint64_t call_site;
    uint32_t tid;
    uint8_t  event_type;
    uint8_t  depth;
    uint8_t  _pad[2];
} poe_entry_t;



typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;
    uint32_t _pad;
    atomic_uint_fast64_t write_pos;
    uint64_t start_ns;
    char _reserved[32];
} poe_header_t;

static poe_header_t *g_header = NULL;
static poe_entry_t *g_entries = NULL;
static int g_fd = -1;
static int g_initialized = 0;
static __thread uint8_t t_depth = 0;
static __thread int t_in_hook = 0;

static uint64_t clock_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void poe_rt_init(void) {
    if (g_initialized) return;
    g_initialized = 1;

    const char *path = getenv("_POE_RT_PATH");
    if (!path) {
        char buf[256];
        snprintf(buf, sizeof(buf), "/tmp/poe-rt-%d.bin", getpid());
        path = buf;
        setenv("_POE_RT_PATH", path, 0);
    }

    uint32_t capacity = POE_RT_DEFAULT_ENTRIES;
    const char *cap_str = getenv("_POE_RT_CAPACITY");
    if (cap_str) {
        uint32_t v = (uint32_t)atoi(cap_str);
        if (v > 0) capacity = v;
    }

    size_t file_size = sizeof(poe_header_t) + capacity * sizeof(poe_entry_t);

    g_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (g_fd < 0) return;

    if (ftruncate(g_fd, file_size) < 0) {
        close(g_fd);
        g_fd = -1;
        return;
    }

    void *map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_fd, 0);
    if (map == MAP_FAILED) {
        close(g_fd);
        g_fd = -1;
        return;
    }

    g_header = (poe_header_t *)map;
    g_entries = (poe_entry_t *)((char *)map + sizeof(poe_header_t));

    g_header->magic = POE_RT_MAGIC;
    g_header->version = POE_RT_VERSION;
    g_header->capacity = capacity;
    atomic_store(&g_header->write_pos, 0);
    g_header->start_ns = clock_ns();
}

static inline void poe_rt_record(void *func, void *call_site, uint8_t event_type) {
    if (!g_header || t_in_hook) return;
    t_in_hook = 1;

    uint64_t pos = atomic_fetch_add(&g_header->write_pos, 1);
    uint32_t idx = (uint32_t)(pos % g_header->capacity);

    poe_entry_t *e = &g_entries[idx];
    e->ts_ns = clock_ns() - g_header->start_ns;
    e->func_addr = (uint64_t)func;
    e->call_site = (uint64_t)call_site;
    e->tid = (uint32_t)gettid();
    e->event_type = event_type;
    e->depth = t_depth;

    t_in_hook = 0;
}

void __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *func, void *call_site) {
    if (!g_initialized) poe_rt_init();
    poe_rt_record(func, call_site, 0);
    if (t_depth < 255) t_depth++;
}

void __attribute__((no_instrument_function))
__cyg_profile_func_exit(void *func, void *call_site) {
    if (t_depth > 0) t_depth--;
    poe_rt_record(func, call_site, 1);
}

static void __attribute__((destructor, no_instrument_function))
poe_rt_fini(void) {
    if (g_header) {
        size_t file_size = sizeof(poe_header_t) + g_header->capacity * sizeof(poe_entry_t);
        msync(g_header, file_size, MS_SYNC);
        munmap(g_header, file_size);
        g_header = NULL;
        g_entries = NULL;
    }
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}
