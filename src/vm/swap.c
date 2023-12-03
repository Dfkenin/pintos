#include "vm/swap.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

static struct bitmap *swap_table;
static struct block *swap_block;
static struct lock swap_lock;

static const int nsector = PGSIZE / BLOCK_SECTOR_SIZE;

void swap_table_init();
size_t swap_out(void *kpage);
void swap_in(size_t index, void *kpage);

void swap_table_init(){
    swap_block = block_get_role(BLOCK_SWAP);
    swap_table = bitmap_create(block_size(swap_block) / nsector); // 0: can swap, 1: can't swap
    lock_init(&swap_lock);
}

size_t swap_out(void *kpage){
    size_t index;
    lock_acquire(&swap_lock);
    index = bitmap_scan_and_flip(swap_table, 0, 1, 0);
    lock_release(&swap_lock);

    void *buffer = kpage;
    for (int i = 0; i < nsector; ++i){
        block_write(swap_block, index * nsector + i, buffer);
        buffer += BLOCK_SECTOR_SIZE;
    }
    return index;
}

void swap_in(size_t index, void *kpage){
    lock_acquire(&swap_lock);
    if (bitmap_test(swap_table, index) == 0){
        sys_exit(-1);
    }

    bitmap_set(swap_table, index, 0);
    lock_release(&swap_lock);

    void *buffer = kpage;
    for (int i = 0; i < nsector; ++i){
        block_read(swap_block, index * nsector + i, buffer);
        buffer += BLOCK_SECTOR_SIZE;
    }
}