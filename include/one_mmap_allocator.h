#pragma once

struct one_mmap_allocator;
struct one_mmap_allocator *one_mmap_allocator_create(uint32_t size);
void *one_mmap_allocator_alloc(struct one_mmap_allocator *a, uint32_t size);
void one_mmap_allocator_destroy(struct one_mmap_allocator *a);
