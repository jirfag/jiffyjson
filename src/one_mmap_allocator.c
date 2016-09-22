#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "internal.h"

struct one_mmap_allocator {
    char *data;
    uint32_t size_left;

    char *src_data;
    uint32_t src_size;
};

struct one_mmap_allocator *one_mmap_allocator_create(uint32_t size) {
    struct one_mmap_allocator *a = malloc(sizeof(*a));
    if (!a)
        return NULL;

    a->data = a->src_data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (a->data == MAP_FAILED) {
        free(a);
        return NULL;
    }

    a->size_left = a->src_size = size;
    return a;
}

void *one_mmap_allocator_alloc(struct one_mmap_allocator *a, uint32_t size) {
    JIFFY_ASSERT(a->size_left >= size);

    void *ret = a->data;
    a->data += size;
    a->size_left -= size;
    return ret;
}

void one_mmap_allocator_destroy(struct one_mmap_allocator *a) {
    int r = munmap(a->src_data, a->src_size);
    JIFFY_ASSERT(r == 0);
    free(a);
}
