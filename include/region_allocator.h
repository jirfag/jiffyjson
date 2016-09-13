#pragma once
struct region_allocator *region_allocator_create();
void region_allocator_add_mem(struct region_allocator *ra, void *buf, uint32_t size);
void *region_allocator_alloc(struct region_allocator *ra, uint32_t size);
void region_allocator_destroy(struct region_allocator *ra);
