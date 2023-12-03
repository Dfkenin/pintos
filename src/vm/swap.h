#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "vm/page.h"
#include "devices/block.h"
#include "threads/vaddr.h"


void swap_table_init();
size_t swap_out(void *kpage);
void swap_in(size_t index, void *kpage);

#endif /* vm/swap.h */