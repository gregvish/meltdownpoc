#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>


#define PAGE_SIZE (0x1000)


uint64_t virt_to_phys(void *virtual_address) {
    int pagemap = 0;
    uint64_t value = 0;
    uint64_t page_frame_number = 0;

    pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap < 0) {
        return 0;
    }

    if (sizeof(uint64_t) !=
        pread(pagemap, &value, sizeof(uint64_t), (((uint64_t)virtual_address) / PAGE_SIZE) * sizeof(uint64_t))) {
        return 0;
    }

    page_frame_number = value & ((1ULL << 54) - 1);
    if (page_frame_number == 0) {
        return 0;
    }

    return page_frame_number * PAGE_SIZE + (uint64_t)virtual_address % PAGE_SIZE;
}


int main(void)
{
    char *test = "Hello. This is a test";

    printf("Data: %s\n", test);
    printf("Virt %p, Phys: %p\n", &test, virt_to_phys(test));

    return 0;
}
