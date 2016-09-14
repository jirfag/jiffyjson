#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include "jvector.h"

typedef void (*mem_area_free_t)(void *p);

struct mem_area {
    void *data;
    uint32_t size;

    void *cur_data;
    uint32_t cur_size;

    mem_area_free_t dtor;
};

jvector_def(mem_area, struct mem_area *);

struct region_allocator {
    jvector(mem_area) areas;
    struct mem_area *cur_area;
};

struct region_allocator *region_allocator_create() {
    struct region_allocator *ra = calloc(1, sizeof(struct region_allocator));
    jvector_ensure(&ra->areas, 8);

    return ra;
}

static struct mem_area *region_allocator_add_mem_impl(struct region_allocator *ra, void *buf, size_t size, mem_area_free_t dtor) {
    struct mem_area *area = malloc(sizeof(*area));
    area->data = area->cur_data = buf;
    area->size = area->cur_size = size;
    area->dtor = dtor;

    struct mem_area **area_ptr = jvector_push_back(&ra->areas);
    *area_ptr = area;

    return area;
}

void region_allocator_add_mem(struct region_allocator *ra, void *buf, size_t size) {
    struct mem_area *area = region_allocator_add_mem_impl(ra, buf, size, NULL);
    if (!ra->cur_area)
        ra->cur_area = area;
}

void *region_allocator_alloc(struct region_allocator *ra, size_t size) {
//    printf("small allocof %zu bytes\n", size);
    const size_t new_area_size = 16384;
    assert(size <= new_area_size);
    struct mem_area *cur_area = ra->cur_area;
    if (!cur_area || cur_area->cur_size < size) {
        void *data = mmap(NULL, new_area_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(data != MAP_FAILED);
        cur_area = ra->cur_area = region_allocator_add_mem_impl(ra, data, new_area_size, free);
       //printf("allocating %zu bytes area\n", new_area_size);
    }

    void *ret = cur_area->cur_data;
    cur_area->cur_data += size;
    cur_area->cur_size -= size;
    return ret;
}

void region_allocator_destroy(struct region_allocator *ra) {
    for (size_t i = 0; i < jvector_size(&ra->areas); ++i) {
        // TODO
    }
}

